rule TTP_XOR_QUAD_CurrentVersionRun_4cf7 {
  strings:
    $key_4cf7 = { 1f 98 [2] 3b 96 [2] 10 ba [2] 3e 98 [2] 2a 83 [2] 25 99 [2] 3b 84 [2] 39 85 [2] 22 83 [2] 3e 84 [2] 22 ab }

  condition:
    any of them
}