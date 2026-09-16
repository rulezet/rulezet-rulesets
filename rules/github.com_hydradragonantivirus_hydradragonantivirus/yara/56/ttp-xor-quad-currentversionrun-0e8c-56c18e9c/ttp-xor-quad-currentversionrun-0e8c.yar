rule TTP_XOR_QUAD_CurrentVersionRun_0e8c {
  strings:
    $key_0e8c = { 5d e3 [2] 79 ed [2] 52 c1 [2] 7c e3 [2] 68 f8 [2] 67 e2 [2] 79 ff [2] 7b fe [2] 60 f8 [2] 7c ff [2] 60 d0 }

  condition:
    any of them
}