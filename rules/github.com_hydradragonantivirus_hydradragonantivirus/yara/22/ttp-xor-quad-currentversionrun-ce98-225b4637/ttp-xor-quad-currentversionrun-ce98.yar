rule TTP_XOR_QUAD_CurrentVersionRun_ce98 {
  strings:
    $key_ce98 = { 9d f7 [2] b9 f9 [2] 92 d5 [2] bc f7 [2] a8 ec [2] a7 f6 [2] b9 eb [2] bb ea [2] a0 ec [2] bc eb [2] a0 c4 }

  condition:
    any of them
}