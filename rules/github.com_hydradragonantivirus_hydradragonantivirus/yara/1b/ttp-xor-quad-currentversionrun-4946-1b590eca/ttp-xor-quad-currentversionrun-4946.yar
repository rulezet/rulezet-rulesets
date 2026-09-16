rule TTP_XOR_QUAD_CurrentVersionRun_4946 {
  strings:
    $key_4946 = { 1a 29 [2] 3e 27 [2] 15 0b [2] 3b 29 [2] 2f 32 [2] 20 28 [2] 3e 35 [2] 3c 34 [2] 27 32 [2] 3b 35 [2] 27 1a }

  condition:
    any of them
}