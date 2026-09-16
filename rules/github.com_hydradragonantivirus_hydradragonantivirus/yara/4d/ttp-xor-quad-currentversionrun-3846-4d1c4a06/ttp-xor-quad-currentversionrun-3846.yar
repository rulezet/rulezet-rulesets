rule TTP_XOR_QUAD_CurrentVersionRun_3846 {
  strings:
    $key_3846 = { 6b 29 [2] 4f 27 [2] 64 0b [2] 4a 29 [2] 5e 32 [2] 51 28 [2] 4f 35 [2] 4d 34 [2] 56 32 [2] 4a 35 [2] 56 1a }

  condition:
    any of them
}