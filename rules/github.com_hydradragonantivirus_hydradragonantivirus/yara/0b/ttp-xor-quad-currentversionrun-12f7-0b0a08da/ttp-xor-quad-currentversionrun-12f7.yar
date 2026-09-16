rule TTP_XOR_QUAD_CurrentVersionRun_12f7 {
  strings:
    $key_12f7 = { 41 98 [2] 65 96 [2] 4e ba [2] 60 98 [2] 74 83 [2] 7b 99 [2] 65 84 [2] 67 85 [2] 7c 83 [2] 60 84 [2] 7c ab }

  condition:
    any of them
}