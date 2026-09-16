rule TTP_XOR_QUAD_CurrentVersionRun_c28c {
  strings:
    $key_c28c = { 91 e3 [2] b5 ed [2] 9e c1 [2] b0 e3 [2] a4 f8 [2] ab e2 [2] b5 ff [2] b7 fe [2] ac f8 [2] b0 ff [2] ac d0 }

  condition:
    any of them
}