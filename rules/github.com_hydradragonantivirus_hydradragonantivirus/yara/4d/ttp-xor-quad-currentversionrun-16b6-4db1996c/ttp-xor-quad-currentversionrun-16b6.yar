rule TTP_XOR_QUAD_CurrentVersionRun_16b6 {
  strings:
    $key_16b6 = { 45 d9 [2] 61 d7 [2] 4a fb [2] 64 d9 [2] 70 c2 [2] 7f d8 [2] 61 c5 [2] 63 c4 [2] 78 c2 [2] 64 c5 [2] 78 ea }

  condition:
    any of them
}