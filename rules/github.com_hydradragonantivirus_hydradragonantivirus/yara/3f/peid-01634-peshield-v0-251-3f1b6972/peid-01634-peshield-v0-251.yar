rule PEiD_01634_PESHiELD_v0_251_ {
  meta:
    description = "[PESHiELD v0.251]"
    ep_only     = "true"

  strings:
    $a = { 5D 83 ED 06 EB 02 EA 04 8D }

  condition:
    $a
}