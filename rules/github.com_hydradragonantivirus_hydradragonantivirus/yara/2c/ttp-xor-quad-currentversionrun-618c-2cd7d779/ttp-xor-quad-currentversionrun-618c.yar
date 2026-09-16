rule TTP_XOR_QUAD_CurrentVersionRun_618c {
  strings:
    $key_618c = { 32 e3 [2] 16 ed [2] 3d c1 [2] 13 e3 [2] 07 f8 [2] 08 e2 [2] 16 ff [2] 14 fe [2] 0f f8 [2] 13 ff [2] 0f d0 }

  condition:
    any of them
}