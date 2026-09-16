rule TTP_XOR_QUAD_CurrentVersionRun_45d1 {
  strings:
    $key_45d1 = { 16 be [2] 32 b0 [2] 19 9c [2] 37 be [2] 23 a5 [2] 2c bf [2] 32 a2 [2] 30 a3 [2] 2b a5 [2] 37 a2 [2] 2b 8d }

  condition:
    any of them
}