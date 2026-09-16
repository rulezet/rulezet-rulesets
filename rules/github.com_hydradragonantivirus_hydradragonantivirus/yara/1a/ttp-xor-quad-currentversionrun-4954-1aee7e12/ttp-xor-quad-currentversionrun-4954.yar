rule TTP_XOR_QUAD_CurrentVersionRun_4954 {
  strings:
    $key_4954 = { 1a 3b [2] 3e 35 [2] 15 19 [2] 3b 3b [2] 2f 20 [2] 20 3a [2] 3e 27 [2] 3c 26 [2] 27 20 [2] 3b 27 [2] 27 08 }

  condition:
    any of them
}