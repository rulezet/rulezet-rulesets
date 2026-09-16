rule TTP_XOR_QUAD_CurrentVersionRun_018c {
  strings:
    $key_018c = { 52 e3 [2] 76 ed [2] 5d c1 [2] 73 e3 [2] 67 f8 [2] 68 e2 [2] 76 ff [2] 74 fe [2] 6f f8 [2] 73 ff [2] 6f d0 }

  condition:
    any of them
}