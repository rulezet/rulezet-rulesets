rule TTP_XOR_QUAD_CurrentVersionRun_7946 {
  strings:
    $key_7946 = { 2a 29 [2] 0e 27 [2] 25 0b [2] 0b 29 [2] 1f 32 [2] 10 28 [2] 0e 35 [2] 0c 34 [2] 17 32 [2] 0b 35 [2] 17 1a }

  condition:
    any of them
}