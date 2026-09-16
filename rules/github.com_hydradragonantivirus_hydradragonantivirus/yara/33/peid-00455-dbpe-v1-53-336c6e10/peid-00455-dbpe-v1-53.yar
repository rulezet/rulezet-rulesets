rule PEiD_00455_DBPE_v1_53_ {
  meta:
    description = "[DBPE v1.53]"
    ep_only     = "true"

  strings:
    $a = { 9C 55 57 56 52 51 53 9C FA E8 ?? ?? ?? ?? 5D 81 ED 5B 53 40 ?? B0 ?? E8 ?? ?? ?? ?? 5E 83 C6 11 B9 27 ?? ?? ?? 30 06 46 49 75 FA }

  condition:
    $a
}