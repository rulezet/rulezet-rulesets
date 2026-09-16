rule TTP_XOR_QUAD_CurrentVersionRun_0490 {
  strings:
    $key_0490 = { 57 ff [2] 73 f1 [2] 58 dd [2] 76 ff [2] 62 e4 [2] 6d fe [2] 73 e3 [2] 71 e2 [2] 6a e4 [2] 76 e3 [2] 6a cc }

  condition:
    any of them
}