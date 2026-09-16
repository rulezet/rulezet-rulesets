rule TTP_XOR_QUAD_CurrentVersionRun_cc8c {
  strings:
    $key_cc8c = { 9f e3 [2] bb ed [2] 90 c1 [2] be e3 [2] aa f8 [2] a5 e2 [2] bb ff [2] b9 fe [2] a2 f8 [2] be ff [2] a2 d0 }

  condition:
    any of them
}