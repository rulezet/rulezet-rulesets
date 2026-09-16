rule TTP_XOR_QUAD_CurrentVersionRun_6490 {
  strings:
    $key_6490 = { 37 ff [2] 13 f1 [2] 38 dd [2] 16 ff [2] 02 e4 [2] 0d fe [2] 13 e3 [2] 11 e2 [2] 0a e4 [2] 16 e3 [2] 0a cc }

  condition:
    any of them
}