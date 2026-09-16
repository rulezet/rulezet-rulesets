rule TTP_XOR_QUAD_CurrentVersionRun_de8c {
  strings:
    $key_de8c = { 8d e3 [2] a9 ed [2] 82 c1 [2] ac e3 [2] b8 f8 [2] b7 e2 [2] a9 ff [2] ab fe [2] b0 f8 [2] ac ff [2] b0 d0 }

  condition:
    any of them
}