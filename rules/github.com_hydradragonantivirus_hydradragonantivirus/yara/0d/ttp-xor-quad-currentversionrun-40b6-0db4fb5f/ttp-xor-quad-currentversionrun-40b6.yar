rule TTP_XOR_QUAD_CurrentVersionRun_40b6 {
  strings:
    $key_40b6 = { 13 d9 [2] 37 d7 [2] 1c fb [2] 32 d9 [2] 26 c2 [2] 29 d8 [2] 37 c5 [2] 35 c4 [2] 2e c2 [2] 32 c5 [2] 2e ea }

  condition:
    any of them
}