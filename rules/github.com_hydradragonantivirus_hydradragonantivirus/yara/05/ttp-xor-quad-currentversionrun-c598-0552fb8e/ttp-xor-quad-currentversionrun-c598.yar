rule TTP_XOR_QUAD_CurrentVersionRun_c598 {
  strings:
    $key_c598 = { 96 f7 [2] b2 f9 [2] 99 d5 [2] b7 f7 [2] a3 ec [2] ac f6 [2] b2 eb [2] b0 ea [2] ab ec [2] b7 eb [2] ab c4 }

  condition:
    any of them
}