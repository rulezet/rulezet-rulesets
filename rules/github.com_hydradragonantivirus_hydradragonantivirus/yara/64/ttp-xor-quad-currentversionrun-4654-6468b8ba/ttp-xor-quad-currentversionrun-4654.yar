rule TTP_XOR_QUAD_CurrentVersionRun_4654 {
  strings:
    $key_4654 = { 15 3b [2] 31 35 [2] 1a 19 [2] 34 3b [2] 20 20 [2] 2f 3a [2] 31 27 [2] 33 26 [2] 28 20 [2] 34 27 [2] 28 08 }

  condition:
    any of them
}