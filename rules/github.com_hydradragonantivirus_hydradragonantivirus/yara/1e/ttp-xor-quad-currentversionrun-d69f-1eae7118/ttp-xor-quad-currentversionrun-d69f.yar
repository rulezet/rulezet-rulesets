rule TTP_XOR_QUAD_CurrentVersionRun_d69f {
  strings:
    $key_d69f = { 85 f0 [2] a1 fe [2] 8a d2 [2] a4 f0 [2] b0 eb [2] bf f1 [2] a1 ec [2] a3 ed [2] b8 eb [2] a4 ec [2] b8 c3 }

  condition:
    any of them
}