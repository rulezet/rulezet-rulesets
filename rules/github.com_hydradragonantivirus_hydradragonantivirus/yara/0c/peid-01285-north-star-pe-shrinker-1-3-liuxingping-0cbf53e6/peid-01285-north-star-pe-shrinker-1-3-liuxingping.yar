rule PEiD_01285_North_Star_PE_Shrinker_1_3____Liuxingping_ {
  meta:
    description = "[North Star PE Shrinker 1.3 -> Liuxingping]"
    ep_only     = "true"

  strings:
    $a = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 }

  condition:
    $a
}