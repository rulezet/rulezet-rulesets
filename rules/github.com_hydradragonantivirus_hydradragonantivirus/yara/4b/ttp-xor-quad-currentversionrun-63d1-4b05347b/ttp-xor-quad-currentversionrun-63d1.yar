rule TTP_XOR_QUAD_CurrentVersionRun_63d1 {
  strings:
    $key_63d1 = { 30 be [2] 14 b0 [2] 3f 9c [2] 11 be [2] 05 a5 [2] 0a bf [2] 14 a2 [2] 16 a3 [2] 0d a5 [2] 11 a2 [2] 0d 8d }

  condition:
    any of them
}