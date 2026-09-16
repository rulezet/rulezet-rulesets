rule PEiD_00661_EXEStealth_2_76_Unregistered____WebtoolMaster_ {
  meta:
    description = "[EXEStealth 2.76 Unregistered -> WebtoolMaster]"
    ep_only     = "false"

  strings:
    $a = { EB ?? 45 78 65 53 74 65 61 6C 74 68 20 56 32 20 53 68 61 72 65 77 61 72 65 20 }

  condition:
    $a
}