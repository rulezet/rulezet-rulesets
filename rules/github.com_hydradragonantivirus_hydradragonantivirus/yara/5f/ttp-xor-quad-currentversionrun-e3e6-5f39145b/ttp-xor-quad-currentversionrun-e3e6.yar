rule TTP_XOR_QUAD_CurrentVersionRun_e3e6 {
  strings:
    $key_e3e6 = { b0 89 [2] 94 87 [2] bf ab [2] 91 89 [2] 85 92 [2] 8a 88 [2] 94 95 [2] 96 94 [2] 8d 92 [2] 91 95 [2] 8d ba }

  condition:
    any of them
}