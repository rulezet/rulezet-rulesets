rule PEiD_00591_EXE32Pack_v1_37_ {
  meta:
    description = "[EXE32Pack v1.37]"
    ep_only     = "true"

  strings:
    $a = { 3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC ?? ?? ?? ?? 02 81 ?? ?? ?? ?? ?? ?? ?? 3B DB 74 01 BE 5D 8B D5 81 ED 4C 8E 40 }

  condition:
    $a
}