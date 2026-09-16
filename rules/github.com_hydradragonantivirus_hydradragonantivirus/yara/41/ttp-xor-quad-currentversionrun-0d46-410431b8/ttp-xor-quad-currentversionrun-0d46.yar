rule TTP_XOR_QUAD_CurrentVersionRun_0d46 {
  strings:
    $key_0d46 = { 5e 29 [2] 7a 27 [2] 51 0b [2] 7f 29 [2] 6b 32 [2] 64 28 [2] 7a 35 [2] 78 34 [2] 63 32 [2] 7f 35 [2] 63 1a }

  condition:
    any of them
}