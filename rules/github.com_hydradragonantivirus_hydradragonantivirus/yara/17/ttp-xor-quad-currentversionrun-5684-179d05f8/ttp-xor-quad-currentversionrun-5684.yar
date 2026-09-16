rule TTP_XOR_QUAD_CurrentVersionRun_5684 {
  strings:
    $key_5684 = { 05 eb [2] 21 e5 [2] 0a c9 [2] 24 eb [2] 30 f0 [2] 3f ea [2] 21 f7 [2] 23 f6 [2] 38 f0 [2] 24 f7 [2] 38 d8 }

  condition:
    any of them
}