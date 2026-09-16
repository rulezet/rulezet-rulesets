rule TTP_XOR_QUAD_CurrentVersionRun_5df7 {
  strings:
    $key_5df7 = { 0e 98 [2] 2a 96 [2] 01 ba [2] 2f 98 [2] 3b 83 [2] 34 99 [2] 2a 84 [2] 28 85 [2] 33 83 [2] 2f 84 [2] 33 ab }

  condition:
    any of them
}