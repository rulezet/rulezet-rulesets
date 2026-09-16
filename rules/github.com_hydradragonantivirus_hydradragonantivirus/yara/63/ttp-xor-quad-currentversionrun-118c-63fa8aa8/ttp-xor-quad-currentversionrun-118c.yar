rule TTP_XOR_QUAD_CurrentVersionRun_118c {
  strings:
    $key_118c = { 42 e3 [2] 66 ed [2] 4d c1 [2] 63 e3 [2] 77 f8 [2] 78 e2 [2] 66 ff [2] 64 fe [2] 7f f8 [2] 63 ff [2] 7f d0 }

  condition:
    any of them
}