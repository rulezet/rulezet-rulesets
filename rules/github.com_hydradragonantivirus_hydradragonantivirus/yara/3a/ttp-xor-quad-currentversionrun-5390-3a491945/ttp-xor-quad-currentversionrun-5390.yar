rule TTP_XOR_QUAD_CurrentVersionRun_5390 {
  strings:
    $key_5390 = { 00 ff [2] 24 f1 [2] 0f dd [2] 21 ff [2] 35 e4 [2] 3a fe [2] 24 e3 [2] 26 e2 [2] 3d e4 [2] 21 e3 [2] 3d cc }

  condition:
    any of them
}