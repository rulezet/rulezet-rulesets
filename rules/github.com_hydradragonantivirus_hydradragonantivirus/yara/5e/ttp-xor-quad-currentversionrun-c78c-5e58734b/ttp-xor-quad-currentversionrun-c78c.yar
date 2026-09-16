rule TTP_XOR_QUAD_CurrentVersionRun_c78c {
  strings:
    $key_c78c = { 94 e3 [2] b0 ed [2] 9b c1 [2] b5 e3 [2] a1 f8 [2] ae e2 [2] b0 ff [2] b2 fe [2] a9 f8 [2] b5 ff [2] a9 d0 }

  condition:
    any of them
}