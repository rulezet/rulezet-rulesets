rule TTP_XOR_QUAD_CurrentVersionRun_538c {
  strings:
    $key_538c = { 00 e3 [2] 24 ed [2] 0f c1 [2] 21 e3 [2] 35 f8 [2] 3a e2 [2] 24 ff [2] 26 fe [2] 3d f8 [2] 21 ff [2] 3d d0 }

  condition:
    any of them
}