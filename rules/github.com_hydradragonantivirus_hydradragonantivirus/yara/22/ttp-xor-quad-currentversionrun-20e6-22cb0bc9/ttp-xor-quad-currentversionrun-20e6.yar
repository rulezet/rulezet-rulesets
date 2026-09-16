rule TTP_XOR_QUAD_CurrentVersionRun_20e6 {
  strings:
    $key_20e6 = { 73 89 [2] 57 87 [2] 7c ab [2] 52 89 [2] 46 92 [2] 49 88 [2] 57 95 [2] 55 94 [2] 4e 92 [2] 52 95 [2] 4e ba }

  condition:
    any of them
}