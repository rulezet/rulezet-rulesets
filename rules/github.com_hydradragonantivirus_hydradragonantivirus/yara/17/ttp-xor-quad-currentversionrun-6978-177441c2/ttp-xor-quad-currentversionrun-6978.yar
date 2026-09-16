rule TTP_XOR_QUAD_CurrentVersionRun_6978 {
  strings:
    $key_6978 = { 3a 17 [2] 1e 19 [2] 35 35 [2] 1b 17 [2] 0f 0c [2] 00 16 [2] 1e 0b [2] 1c 0a [2] 07 0c [2] 1b 0b [2] 07 24 }

  condition:
    any of them
}