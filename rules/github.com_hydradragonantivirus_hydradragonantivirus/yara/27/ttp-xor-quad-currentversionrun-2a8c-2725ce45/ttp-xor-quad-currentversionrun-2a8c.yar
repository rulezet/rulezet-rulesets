rule TTP_XOR_QUAD_CurrentVersionRun_2a8c {
  strings:
    $key_2a8c = { 79 e3 [2] 5d ed [2] 76 c1 [2] 58 e3 [2] 4c f8 [2] 43 e2 [2] 5d ff [2] 5f fe [2] 44 f8 [2] 58 ff [2] 44 d0 }

  condition:
    any of them
}