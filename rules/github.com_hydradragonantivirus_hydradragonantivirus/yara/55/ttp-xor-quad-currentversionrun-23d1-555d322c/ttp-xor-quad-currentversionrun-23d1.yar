rule TTP_XOR_QUAD_CurrentVersionRun_23d1 {
  strings:
    $key_23d1 = { 70 be [2] 54 b0 [2] 7f 9c [2] 51 be [2] 45 a5 [2] 4a bf [2] 54 a2 [2] 56 a3 [2] 4d a5 [2] 51 a2 [2] 4d 8d }

  condition:
    any of them
}