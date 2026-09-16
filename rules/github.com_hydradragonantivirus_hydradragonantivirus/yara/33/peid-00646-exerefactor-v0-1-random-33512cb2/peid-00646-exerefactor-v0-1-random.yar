rule PEiD_00646_EXERefactor_V0_1____random_ {
  meta:
    description = "[EXERefactor V0.1 -> random]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 81 EC 90 0B 00 00 53 56 57 E9 58 8C 01 00 55 53 43 41 54 49 4F 4E }

  condition:
    $a
}