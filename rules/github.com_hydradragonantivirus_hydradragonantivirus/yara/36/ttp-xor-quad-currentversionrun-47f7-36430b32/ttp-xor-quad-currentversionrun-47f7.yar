rule TTP_XOR_QUAD_CurrentVersionRun_47f7 {
  strings:
    $key_47f7 = { 14 98 [2] 30 96 [2] 1b ba [2] 35 98 [2] 21 83 [2] 2e 99 [2] 30 84 [2] 32 85 [2] 29 83 [2] 35 84 [2] 29 ab }

  condition:
    any of them
}