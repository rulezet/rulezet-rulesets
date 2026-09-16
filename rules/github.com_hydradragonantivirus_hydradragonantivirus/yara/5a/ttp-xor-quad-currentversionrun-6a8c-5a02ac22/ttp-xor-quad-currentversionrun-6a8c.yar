rule TTP_XOR_QUAD_CurrentVersionRun_6a8c {
  strings:
    $key_6a8c = { 39 e3 [2] 1d ed [2] 36 c1 [2] 18 e3 [2] 0c f8 [2] 03 e2 [2] 1d ff [2] 1f fe [2] 04 f8 [2] 18 ff [2] 04 d0 }

  condition:
    any of them
}