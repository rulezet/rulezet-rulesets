rule PEiD_02024_Safe_2_0_ {
  meta:
    description = "[Safe 2.0]"
    ep_only     = "false"

  strings:
    $a = { 83 EC 10 53 56 57 E8 C4 01 00 }

  condition:
    $a
}