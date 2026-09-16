rule TTP_XOR_QUAD_CurrentVersionRun_76d1 {
  strings:
    $key_76d1 = { 25 be [2] 01 b0 [2] 2a 9c [2] 04 be [2] 10 a5 [2] 1f bf [2] 01 a2 [2] 03 a3 [2] 18 a5 [2] 04 a2 [2] 18 8d }

  condition:
    any of them
}