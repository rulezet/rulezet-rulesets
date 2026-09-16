rule TTP_XOR_QUAD_CurrentVersionRun_d398 {
  strings:
    $key_d398 = { 80 f7 [2] a4 f9 [2] 8f d5 [2] a1 f7 [2] b5 ec [2] ba f6 [2] a4 eb [2] a6 ea [2] bd ec [2] a1 eb [2] bd c4 }

  condition:
    any of them
}