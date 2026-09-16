rule TTP_XOR_QUAD_CurrentVersionRun_d88c {
  strings:
    $key_d88c = { 8b e3 [2] af ed [2] 84 c1 [2] aa e3 [2] be f8 [2] b1 e2 [2] af ff [2] ad fe [2] b6 f8 [2] aa ff [2] b6 d0 }

  condition:
    any of them
}