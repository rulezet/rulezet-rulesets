rule TTP_XOR_QUAD_CurrentVersionRun_56f7 {
  strings:
    $key_56f7 = { 05 98 [2] 21 96 [2] 0a ba [2] 24 98 [2] 30 83 [2] 3f 99 [2] 21 84 [2] 23 85 [2] 38 83 [2] 24 84 [2] 38 ab }

  condition:
    any of them
}