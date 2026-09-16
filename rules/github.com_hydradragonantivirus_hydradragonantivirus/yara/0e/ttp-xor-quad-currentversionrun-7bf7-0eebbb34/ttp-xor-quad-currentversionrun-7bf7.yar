rule TTP_XOR_QUAD_CurrentVersionRun_7bf7 {
  strings:
    $key_7bf7 = { 28 98 [2] 0c 96 [2] 27 ba [2] 09 98 [2] 1d 83 [2] 12 99 [2] 0c 84 [2] 0e 85 [2] 15 83 [2] 09 84 [2] 15 ab }

  condition:
    any of them
}