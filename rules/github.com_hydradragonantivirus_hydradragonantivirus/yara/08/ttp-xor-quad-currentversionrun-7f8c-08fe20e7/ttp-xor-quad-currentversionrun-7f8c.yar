rule TTP_XOR_QUAD_CurrentVersionRun_7f8c {
  strings:
    $key_7f8c = { 2c e3 [2] 08 ed [2] 23 c1 [2] 0d e3 [2] 19 f8 [2] 16 e2 [2] 08 ff [2] 0a fe [2] 11 f8 [2] 0d ff [2] 11 d0 }

  condition:
    any of them
}