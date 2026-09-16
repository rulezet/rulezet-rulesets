rule PEiD_01032_MicroJoiner_1_6____coban2k_ {
  meta:
    description = "[MicroJoiner 1.6 -> coban2k]"
    ep_only     = "true"

  strings:
    $a = { 33 C0 64 8B 38 48 8B C8 F2 AF AF 8B 1F 66 33 DB 66 81 3B }

  condition:
    $a
}