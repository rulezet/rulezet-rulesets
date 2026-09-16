rule TTP_XOR_QUAD_CurrentVersionRun_d18c {
  strings:
    $key_d18c = { 82 e3 [2] a6 ed [2] 8d c1 [2] a3 e3 [2] b7 f8 [2] b8 e2 [2] a6 ff [2] a4 fe [2] bf f8 [2] a3 ff [2] bf d0 }

  condition:
    any of them
}