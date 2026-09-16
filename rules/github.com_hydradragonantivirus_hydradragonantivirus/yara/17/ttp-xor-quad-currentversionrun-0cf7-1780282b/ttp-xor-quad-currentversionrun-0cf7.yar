rule TTP_XOR_QUAD_CurrentVersionRun_0cf7 {
  strings:
    $key_0cf7 = { 5f 98 [2] 7b 96 [2] 50 ba [2] 7e 98 [2] 6a 83 [2] 65 99 [2] 7b 84 [2] 79 85 [2] 62 83 [2] 7e 84 [2] 62 ab }

  condition:
    any of them
}