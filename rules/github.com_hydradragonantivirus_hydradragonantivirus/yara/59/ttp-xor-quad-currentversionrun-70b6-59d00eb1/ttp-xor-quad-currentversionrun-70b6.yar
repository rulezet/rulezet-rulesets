rule TTP_XOR_QUAD_CurrentVersionRun_70b6 {
  strings:
    $key_70b6 = { 23 d9 [2] 07 d7 [2] 2c fb [2] 02 d9 [2] 16 c2 [2] 19 d8 [2] 07 c5 [2] 05 c4 [2] 1e c2 [2] 02 c5 [2] 1e ea }

  condition:
    any of them
}