rule TTP_XOR_QUAD_CurrentVersionRun_2b84 {
  strings:
    $key_2b84 = { 78 eb [2] 5c e5 [2] 77 c9 [2] 59 eb [2] 4d f0 [2] 42 ea [2] 5c f7 [2] 5e f6 [2] 45 f0 [2] 59 f7 [2] 45 d8 }

  condition:
    any of them
}