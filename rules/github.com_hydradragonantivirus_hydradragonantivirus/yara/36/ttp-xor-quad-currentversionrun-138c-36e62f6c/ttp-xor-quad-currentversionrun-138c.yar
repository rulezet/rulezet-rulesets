rule TTP_XOR_QUAD_CurrentVersionRun_138c {
  strings:
    $key_138c = { 40 e3 [2] 64 ed [2] 4f c1 [2] 61 e3 [2] 75 f8 [2] 7a e2 [2] 64 ff [2] 66 fe [2] 7d f8 [2] 61 ff [2] 7d d0 }

  condition:
    any of them
}