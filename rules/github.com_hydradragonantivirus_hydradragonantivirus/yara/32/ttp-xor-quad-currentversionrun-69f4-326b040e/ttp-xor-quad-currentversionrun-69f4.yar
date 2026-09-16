rule TTP_XOR_QUAD_CurrentVersionRun_69f4 {
  strings:
    $key_69f4 = { 3a 9b [2] 1e 95 [2] 35 b9 [2] 1b 9b [2] 0f 80 [2] 00 9a [2] 1e 87 [2] 1c 86 [2] 07 80 [2] 1b 87 [2] 07 a8 }

  condition:
    any of them
}