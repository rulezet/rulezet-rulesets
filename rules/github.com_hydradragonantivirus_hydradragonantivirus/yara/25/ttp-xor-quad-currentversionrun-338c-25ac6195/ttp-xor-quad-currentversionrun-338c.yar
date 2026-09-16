rule TTP_XOR_QUAD_CurrentVersionRun_338c {
  strings:
    $key_338c = { 60 e3 [2] 44 ed [2] 6f c1 [2] 41 e3 [2] 55 f8 [2] 5a e2 [2] 44 ff [2] 46 fe [2] 5d f8 [2] 41 ff [2] 5d d0 }

  condition:
    any of them
}