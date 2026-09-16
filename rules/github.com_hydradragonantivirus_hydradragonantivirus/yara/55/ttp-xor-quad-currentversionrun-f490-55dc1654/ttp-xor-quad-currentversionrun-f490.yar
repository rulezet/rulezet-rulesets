rule TTP_XOR_QUAD_CurrentVersionRun_f490 {
  strings:
    $key_f490 = { a7 ff [2] 83 f1 [2] a8 dd [2] 86 ff [2] 92 e4 [2] 9d fe [2] 83 e3 [2] 81 e2 [2] 9a e4 [2] 86 e3 [2] 9a cc }

  condition:
    any of them
}