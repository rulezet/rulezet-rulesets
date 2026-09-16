rule TTP_XOR_QUAD_CurrentVersionRun_2b8c {
  strings:
    $key_2b8c = { 78 e3 [2] 5c ed [2] 77 c1 [2] 59 e3 [2] 4d f8 [2] 42 e2 [2] 5c ff [2] 5e fe [2] 45 f8 [2] 59 ff [2] 45 d0 }

  condition:
    any of them
}