rule TTP_XOR_QUAD_CurrentVersionRun_00b6 {
  strings:
    $key_00b6 = { 53 d9 [2] 77 d7 [2] 5c fb [2] 72 d9 [2] 66 c2 [2] 69 d8 [2] 77 c5 [2] 75 c4 [2] 6e c2 [2] 72 c5 [2] 6e ea }

  condition:
    any of them
}