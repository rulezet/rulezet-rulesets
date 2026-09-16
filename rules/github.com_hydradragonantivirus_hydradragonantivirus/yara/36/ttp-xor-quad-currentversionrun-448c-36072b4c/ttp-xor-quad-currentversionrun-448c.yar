rule TTP_XOR_QUAD_CurrentVersionRun_448c {
  strings:
    $key_448c = { 17 e3 [2] 33 ed [2] 18 c1 [2] 36 e3 [2] 22 f8 [2] 2d e2 [2] 33 ff [2] 31 fe [2] 2a f8 [2] 36 ff [2] 2a d0 }

  condition:
    any of them
}