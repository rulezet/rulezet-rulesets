rule TTP_XOR_QUAD_CurrentVersionRun_52f7 {
  strings:
    $key_52f7 = { 01 98 [2] 25 96 [2] 0e ba [2] 20 98 [2] 34 83 [2] 3b 99 [2] 25 84 [2] 27 85 [2] 3c 83 [2] 20 84 [2] 3c ab }

  condition:
    any of them
}