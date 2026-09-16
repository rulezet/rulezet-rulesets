rule TTP_XOR_QUAD_CurrentVersionRun_60f7 {
  strings:
    $key_60f7 = { 33 98 [2] 17 96 [2] 3c ba [2] 12 98 [2] 06 83 [2] 09 99 [2] 17 84 [2] 15 85 [2] 0e 83 [2] 12 84 [2] 0e ab }

  condition:
    any of them
}