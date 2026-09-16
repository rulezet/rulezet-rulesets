rule TTP_XOR_QUAD_CurrentVersionRun_738c {
  strings:
    $key_738c = { 20 e3 [2] 04 ed [2] 2f c1 [2] 01 e3 [2] 15 f8 [2] 1a e2 [2] 04 ff [2] 06 fe [2] 1d f8 [2] 01 ff [2] 1d d0 }

  condition:
    any of them
}