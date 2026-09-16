rule TTP_XOR_QUAD_CurrentVersionRun_1b8c {
  strings:
    $key_1b8c = { 48 e3 [2] 6c ed [2] 47 c1 [2] 69 e3 [2] 7d f8 [2] 72 e2 [2] 6c ff [2] 6e fe [2] 75 f8 [2] 69 ff [2] 75 d0 }

  condition:
    any of them
}