rule TTP_XOR_QUAD_CurrentVersionRun_4df7 {
  strings:
    $key_4df7 = { 1e 98 [2] 3a 96 [2] 11 ba [2] 3f 98 [2] 2b 83 [2] 24 99 [2] 3a 84 [2] 38 85 [2] 23 83 [2] 3f 84 [2] 23 ab }

  condition:
    any of them
}