rule TTP_XOR_QUAD_CurrentVersionRun_27f7 {
  strings:
    $key_27f7 = { 74 98 [2] 50 96 [2] 7b ba [2] 55 98 [2] 41 83 [2] 4e 99 [2] 50 84 [2] 52 85 [2] 49 83 [2] 55 84 [2] 49 ab }

  condition:
    any of them
}