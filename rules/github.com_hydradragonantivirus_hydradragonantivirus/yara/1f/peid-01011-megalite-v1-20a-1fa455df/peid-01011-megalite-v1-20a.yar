rule PEiD_01011_MEGALITE_v1_20a_ {
  meta:
    description = "[MEGALITE v1.20a]"
    ep_only     = "true"

  strings:
    $a = { B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 2D 73 ?? 72 ?? B4 09 BA ?? ?? CD 21 CD 90 }

  condition:
    $a
}