rule TTP_XOR_QUAD_CurrentVersionRun_ca98 {
  strings:
    $key_ca98 = { 99 f7 [2] bd f9 [2] 96 d5 [2] b8 f7 [2] ac ec [2] a3 f6 [2] bd eb [2] bf ea [2] a4 ec [2] b8 eb [2] a4 c4 }

  condition:
    any of them
}