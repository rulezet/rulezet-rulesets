rule TTP_XOR_QUAD_CurrentVersionRun_30b6 {
  strings:
    $key_30b6 = { 63 d9 [2] 47 d7 [2] 6c fb [2] 42 d9 [2] 56 c2 [2] 59 d8 [2] 47 c5 [2] 45 c4 [2] 5e c2 [2] 42 c5 [2] 5e ea }

  condition:
    any of them
}