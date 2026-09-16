rule TTP_XOR_QUAD_CurrentVersionRun_10f7 {
  strings:
    $key_10f7 = { 43 98 [2] 67 96 [2] 4c ba [2] 62 98 [2] 76 83 [2] 79 99 [2] 67 84 [2] 65 85 [2] 7e 83 [2] 62 84 [2] 7e ab }

  condition:
    any of them
}