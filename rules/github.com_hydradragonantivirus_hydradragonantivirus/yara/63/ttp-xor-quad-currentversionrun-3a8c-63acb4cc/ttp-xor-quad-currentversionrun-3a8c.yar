rule TTP_XOR_QUAD_CurrentVersionRun_3a8c {
  strings:
    $key_3a8c = { 69 e3 [2] 4d ed [2] 66 c1 [2] 48 e3 [2] 5c f8 [2] 53 e2 [2] 4d ff [2] 4f fe [2] 54 f8 [2] 48 ff [2] 54 d0 }

  condition:
    any of them
}