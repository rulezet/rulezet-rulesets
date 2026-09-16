rule TTP_XOR_QUAD_CurrentVersionRun_30e6 {
  strings:
    $key_30e6 = { 63 89 [2] 47 87 [2] 6c ab [2] 42 89 [2] 56 92 [2] 59 88 [2] 47 95 [2] 45 94 [2] 5e 92 [2] 42 95 [2] 5e ba }

  condition:
    any of them
}