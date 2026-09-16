rule TTP_XOR_QUAD_CurrentVersionRun_4978 {
  strings:
    $key_4978 = { 1a 17 [2] 3e 19 [2] 15 35 [2] 3b 17 [2] 2f 0c [2] 20 16 [2] 3e 0b [2] 3c 0a [2] 27 0c [2] 3b 0b [2] 27 24 }

  condition:
    any of them
}