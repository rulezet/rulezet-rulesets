rule TTP_XOR_QUAD_CurrentVersionRun_53d5 {
  strings:
    $key_53d5 = { 00 ba [2] 24 b4 [2] 0f 98 [2] 21 ba [2] 35 a1 [2] 3a bb [2] 24 a6 [2] 26 a7 [2] 3d a1 [2] 21 a6 [2] 3d 89 }

  condition:
    any of them
}