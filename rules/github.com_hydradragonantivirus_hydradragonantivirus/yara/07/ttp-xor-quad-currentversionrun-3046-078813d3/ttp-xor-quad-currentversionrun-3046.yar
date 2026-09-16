rule TTP_XOR_QUAD_CurrentVersionRun_3046 {
  strings:
    $key_3046 = { 63 29 [2] 47 27 [2] 6c 0b [2] 42 29 [2] 56 32 [2] 59 28 [2] 47 35 [2] 45 34 [2] 5e 32 [2] 42 35 [2] 5e 1a }

  condition:
    any of them
}