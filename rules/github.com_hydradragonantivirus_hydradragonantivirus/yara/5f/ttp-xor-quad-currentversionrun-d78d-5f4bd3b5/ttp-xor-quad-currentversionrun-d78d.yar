rule TTP_XOR_QUAD_CurrentVersionRun_d78d {
  strings:
    $key_d78d = { 84 e2 [2] a0 ec [2] 8b c0 [2] a5 e2 [2] b1 f9 [2] be e3 [2] a0 fe [2] a2 ff [2] b9 f9 [2] a5 fe [2] b9 d1 }

  condition:
    any of them
}