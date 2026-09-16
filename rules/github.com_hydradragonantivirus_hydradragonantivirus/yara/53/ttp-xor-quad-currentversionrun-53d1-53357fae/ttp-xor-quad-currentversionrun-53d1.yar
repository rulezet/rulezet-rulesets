rule TTP_XOR_QUAD_CurrentVersionRun_53d1 {
  strings:
    $key_53d1 = { 00 be [2] 24 b0 [2] 0f 9c [2] 21 be [2] 35 a5 [2] 3a bf [2] 24 a2 [2] 26 a3 [2] 3d a5 [2] 21 a2 [2] 3d 8d }

  condition:
    any of them
}