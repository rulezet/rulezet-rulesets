rule PEiD_01033_MicroJoiner_1_7____coban2k_ {
  meta:
    description = "[MicroJoiner 1.7 -> coban2k]"
    ep_only     = "true"

  strings:
    $a = { BF 00 10 40 00 8D 5F 21 6A 0A 58 6A 04 59 60 57 E8 8E 00 00 00 }

  condition:
    $a
}