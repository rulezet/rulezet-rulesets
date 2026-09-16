rule TTP_XOR_QUAD_CurrentVersionRun_2490 {
  strings:
    $key_2490 = { 77 ff [2] 53 f1 [2] 78 dd [2] 56 ff [2] 42 e4 [2] 4d fe [2] 53 e3 [2] 51 e2 [2] 4a e4 [2] 56 e3 [2] 4a cc }

  condition:
    any of them
}