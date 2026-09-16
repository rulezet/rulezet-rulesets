rule TTP_XOR_QUAD_CurrentVersionRun_7842 {
  strings:
    $key_7842 = { 2b 2d [2] 0f 23 [2] 24 0f [2] 0a 2d [2] 1e 36 [2] 11 2c [2] 0f 31 [2] 0d 30 [2] 16 36 [2] 0a 31 [2] 16 1e }

  condition:
    any of them
}