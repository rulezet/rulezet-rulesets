rule TTP_XOR_QUAD_CurrentVersionRun_6b8c {
  strings:
    $key_6b8c = { 38 e3 [2] 1c ed [2] 37 c1 [2] 19 e3 [2] 0d f8 [2] 02 e2 [2] 1c ff [2] 1e fe [2] 05 f8 [2] 19 ff [2] 05 d0 }

  condition:
    any of them
}