rule TTP_XOR_QUAD_CurrentVersionRun_22f7 {
  strings:
    $key_22f7 = { 71 98 [2] 55 96 [2] 7e ba [2] 50 98 [2] 44 83 [2] 4b 99 [2] 55 84 [2] 57 85 [2] 4c 83 [2] 50 84 [2] 4c ab }

  condition:
    any of them
}