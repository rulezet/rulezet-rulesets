rule TTP_XOR_QUAD_CurrentVersionRun_69e8 {
  strings:
    $key_69e8 = { 3a 87 [2] 1e 89 [2] 35 a5 [2] 1b 87 [2] 0f 9c [2] 00 86 [2] 1e 9b [2] 1c 9a [2] 07 9c [2] 1b 9b [2] 07 b4 }

  condition:
    any of them
}