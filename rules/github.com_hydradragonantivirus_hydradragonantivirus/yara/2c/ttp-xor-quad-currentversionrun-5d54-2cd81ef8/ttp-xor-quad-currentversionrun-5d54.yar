rule TTP_XOR_QUAD_CurrentVersionRun_5d54 {
  strings:
    $key_5d54 = { 0e 3b [2] 2a 35 [2] 01 19 [2] 2f 3b [2] 3b 20 [2] 34 3a [2] 2a 27 [2] 28 26 [2] 33 20 [2] 2f 27 [2] 33 08 }

  condition:
    any of them
}