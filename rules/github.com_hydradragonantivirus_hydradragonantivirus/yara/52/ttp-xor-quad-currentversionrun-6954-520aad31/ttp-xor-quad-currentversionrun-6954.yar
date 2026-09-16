rule TTP_XOR_QUAD_CurrentVersionRun_6954 {
  strings:
    $key_6954 = { 3a 3b [2] 1e 35 [2] 35 19 [2] 1b 3b [2] 0f 20 [2] 00 3a [2] 1e 27 [2] 1c 26 [2] 07 20 [2] 1b 27 [2] 07 08 }

  condition:
    any of them
}