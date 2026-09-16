rule TTP_XOR_QUAD_CurrentVersionRun_3184 {
  strings:
    $key_3184 = { 62 eb [2] 46 e5 [2] 6d c9 [2] 43 eb [2] 57 f0 [2] 58 ea [2] 46 f7 [2] 44 f6 [2] 5f f0 [2] 43 f7 [2] 5f d8 }

  condition:
    any of them
}