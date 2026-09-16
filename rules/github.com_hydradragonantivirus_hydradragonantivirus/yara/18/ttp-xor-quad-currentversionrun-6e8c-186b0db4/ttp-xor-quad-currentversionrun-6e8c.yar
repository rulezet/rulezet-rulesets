rule TTP_XOR_QUAD_CurrentVersionRun_6e8c {
  strings:
    $key_6e8c = { 3d e3 [2] 19 ed [2] 32 c1 [2] 1c e3 [2] 08 f8 [2] 07 e2 [2] 19 ff [2] 1b fe [2] 00 f8 [2] 1c ff [2] 00 d0 }

  condition:
    any of them
}