rule TTP_XOR_QUAD_CurrentVersionRun_32b3 {
  strings:
    $key_32b3 = { 61 dc [2] 45 d2 [2] 6e fe [2] 40 dc [2] 54 c7 [2] 5b dd [2] 45 c0 [2] 47 c1 [2] 5c c7 [2] 40 c0 [2] 5c ef }

  condition:
    any of them
}