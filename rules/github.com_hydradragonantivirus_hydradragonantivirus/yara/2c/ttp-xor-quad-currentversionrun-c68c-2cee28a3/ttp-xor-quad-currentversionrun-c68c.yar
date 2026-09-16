rule TTP_XOR_QUAD_CurrentVersionRun_c68c {
  strings:
    $key_c68c = { 95 e3 [2] b1 ed [2] 9a c1 [2] b4 e3 [2] a0 f8 [2] af e2 [2] b1 ff [2] b3 fe [2] a8 f8 [2] b4 ff [2] a8 d0 }

  condition:
    any of them
}