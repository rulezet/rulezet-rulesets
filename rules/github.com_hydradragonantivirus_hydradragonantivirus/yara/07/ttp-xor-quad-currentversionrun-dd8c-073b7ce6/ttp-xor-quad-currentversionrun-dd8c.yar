rule TTP_XOR_QUAD_CurrentVersionRun_dd8c {
  strings:
    $key_dd8c = { 8e e3 [2] aa ed [2] 81 c1 [2] af e3 [2] bb f8 [2] b4 e2 [2] aa ff [2] a8 fe [2] b3 f8 [2] af ff [2] b3 d0 }

  condition:
    any of them
}