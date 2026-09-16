rule TTP_XOR_QUAD_CurrentVersionRun_ca8c {
  strings:
    $key_ca8c = { 99 e3 [2] bd ed [2] 96 c1 [2] b8 e3 [2] ac f8 [2] a3 e2 [2] bd ff [2] bf fe [2] a4 f8 [2] b8 ff [2] a4 d0 }

  condition:
    any of them
}