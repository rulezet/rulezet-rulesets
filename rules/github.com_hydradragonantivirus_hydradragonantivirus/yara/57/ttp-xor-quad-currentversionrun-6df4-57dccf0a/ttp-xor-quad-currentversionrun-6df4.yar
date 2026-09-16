rule TTP_XOR_QUAD_CurrentVersionRun_6df4 {
  strings:
    $key_6df4 = { 3e 9b [2] 1a 95 [2] 31 b9 [2] 1f 9b [2] 0b 80 [2] 04 9a [2] 1a 87 [2] 18 86 [2] 03 80 [2] 1f 87 [2] 03 a8 }

  condition:
    any of them
}