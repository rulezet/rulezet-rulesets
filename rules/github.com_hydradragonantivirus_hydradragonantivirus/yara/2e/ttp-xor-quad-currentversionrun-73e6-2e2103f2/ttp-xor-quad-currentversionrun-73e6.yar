rule TTP_XOR_QUAD_CurrentVersionRun_73e6 {
  strings:
    $key_73e6 = { 20 89 [2] 04 87 [2] 2f ab [2] 01 89 [2] 15 92 [2] 1a 88 [2] 04 95 [2] 06 94 [2] 1d 92 [2] 01 95 [2] 1d ba }

  condition:
    any of them
}