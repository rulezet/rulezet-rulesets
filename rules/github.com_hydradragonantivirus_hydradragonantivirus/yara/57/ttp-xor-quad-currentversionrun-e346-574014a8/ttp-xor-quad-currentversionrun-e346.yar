rule TTP_XOR_QUAD_CurrentVersionRun_e346 {
  strings:
    $key_e346 = { b0 29 [2] 94 27 [2] bf 0b [2] 91 29 [2] 85 32 [2] 8a 28 [2] 94 35 [2] 96 34 [2] 8d 32 [2] 91 35 [2] 8d 1a }

  condition:
    any of them
}