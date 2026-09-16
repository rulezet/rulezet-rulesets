rule TTP_XOR_QUAD_CurrentVersionRun_f1e6 {
  strings:
    $key_f1e6 = { a2 89 [2] 86 87 [2] ad ab [2] 83 89 [2] 97 92 [2] 98 88 [2] 86 95 [2] 84 94 [2] 9f 92 [2] 83 95 [2] 9f ba }

  condition:
    any of them
}