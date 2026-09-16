rule TTP_XOR_QUAD_CurrentVersionRun_0046 {
  strings:
    $key_0046 = { 53 29 [2] 77 27 [2] 5c 0b [2] 72 29 [2] 66 32 [2] 69 28 [2] 77 35 [2] 75 34 [2] 6e 32 [2] 72 35 [2] 6e 1a }

  condition:
    any of them
}