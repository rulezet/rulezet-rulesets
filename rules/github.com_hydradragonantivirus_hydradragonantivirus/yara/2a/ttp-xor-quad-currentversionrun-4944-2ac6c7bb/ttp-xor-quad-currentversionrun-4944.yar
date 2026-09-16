rule TTP_XOR_QUAD_CurrentVersionRun_4944 {
  strings:
    $key_4944 = { 1a 2b [2] 3e 25 [2] 15 09 [2] 3b 2b [2] 2f 30 [2] 20 2a [2] 3e 37 [2] 3c 36 [2] 27 30 [2] 3b 37 [2] 27 18 }

  condition:
    any of them
}