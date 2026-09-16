rule TTP_XOR_QUAD_CurrentVersionRun_25b3 {
  strings:
    $key_25b3 = { 76 dc [2] 52 d2 [2] 79 fe [2] 57 dc [2] 43 c7 [2] 4c dd [2] 52 c0 [2] 50 c1 [2] 4b c7 [2] 57 c0 [2] 4b ef }

  condition:
    any of them
}