rule TTP_XOR_QUAD_CurrentVersionRun_35e6 {
  strings:
    $key_35e6 = { 66 89 [2] 42 87 [2] 69 ab [2] 47 89 [2] 53 92 [2] 5c 88 [2] 42 95 [2] 40 94 [2] 5b 92 [2] 47 95 [2] 5b ba }

  condition:
    any of them
}