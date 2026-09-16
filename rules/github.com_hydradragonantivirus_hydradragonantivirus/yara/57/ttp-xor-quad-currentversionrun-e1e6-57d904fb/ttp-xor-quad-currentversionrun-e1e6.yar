rule TTP_XOR_QUAD_CurrentVersionRun_e1e6 {
  strings:
    $key_e1e6 = { b2 89 [2] 96 87 [2] bd ab [2] 93 89 [2] 87 92 [2] 88 88 [2] 96 95 [2] 94 94 [2] 8f 92 [2] 93 95 [2] 8f ba }

  condition:
    any of them
}