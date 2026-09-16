rule TTP_XOR_QUAD_CurrentVersionRun_4490 {
  strings:
    $key_4490 = { 17 ff [2] 33 f1 [2] 18 dd [2] 36 ff [2] 22 e4 [2] 2d fe [2] 33 e3 [2] 31 e2 [2] 2a e4 [2] 36 e3 [2] 2a cc }

  condition:
    any of them
}