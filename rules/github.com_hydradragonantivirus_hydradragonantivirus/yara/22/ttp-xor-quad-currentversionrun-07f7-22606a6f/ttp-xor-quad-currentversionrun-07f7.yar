rule TTP_XOR_QUAD_CurrentVersionRun_07f7 {
  strings:
    $key_07f7 = { 54 98 [2] 70 96 [2] 5b ba [2] 75 98 [2] 61 83 [2] 6e 99 [2] 70 84 [2] 72 85 [2] 69 83 [2] 75 84 [2] 69 ab }

  condition:
    any of them
}