rule TTP_XOR_QUAD_CurrentVersionRun_36f7 {
  strings:
    $key_36f7 = { 65 98 [2] 41 96 [2] 6a ba [2] 44 98 [2] 50 83 [2] 5f 99 [2] 41 84 [2] 43 85 [2] 58 83 [2] 44 84 [2] 58 ab }

  condition:
    any of them
}