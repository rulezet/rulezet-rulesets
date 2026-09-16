rule TTP_XOR_QUAD_CurrentVersionRun_06b6 {
  strings:
    $key_06b6 = { 55 d9 [2] 71 d7 [2] 5a fb [2] 74 d9 [2] 60 c2 [2] 6f d8 [2] 71 c5 [2] 73 c4 [2] 68 c2 [2] 74 c5 [2] 68 ea }

  condition:
    any of them
}