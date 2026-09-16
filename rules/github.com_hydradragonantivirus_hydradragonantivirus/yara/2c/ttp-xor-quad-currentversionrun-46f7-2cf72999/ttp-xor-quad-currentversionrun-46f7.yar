rule TTP_XOR_QUAD_CurrentVersionRun_46f7 {
  strings:
    $key_46f7 = { 15 98 [2] 31 96 [2] 1a ba [2] 34 98 [2] 20 83 [2] 2f 99 [2] 31 84 [2] 33 85 [2] 28 83 [2] 34 84 [2] 28 ab }

  condition:
    any of them
}