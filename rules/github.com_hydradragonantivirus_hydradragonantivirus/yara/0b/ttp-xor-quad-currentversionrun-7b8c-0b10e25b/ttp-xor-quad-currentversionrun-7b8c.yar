rule TTP_XOR_QUAD_CurrentVersionRun_7b8c {
  strings:
    $key_7b8c = { 28 e3 [2] 0c ed [2] 27 c1 [2] 09 e3 [2] 1d f8 [2] 12 e2 [2] 0c ff [2] 0e fe [2] 15 f8 [2] 09 ff [2] 15 d0 }

  condition:
    any of them
}