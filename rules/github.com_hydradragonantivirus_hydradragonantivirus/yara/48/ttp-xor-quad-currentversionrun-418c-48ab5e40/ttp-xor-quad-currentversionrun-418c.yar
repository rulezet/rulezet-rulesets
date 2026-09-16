rule TTP_XOR_QUAD_CurrentVersionRun_418c {
  strings:
    $key_418c = { 12 e3 [2] 36 ed [2] 1d c1 [2] 33 e3 [2] 27 f8 [2] 28 e2 [2] 36 ff [2] 34 fe [2] 2f f8 [2] 33 ff [2] 2f d0 }

  condition:
    any of them
}