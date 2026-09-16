rule TTP_XOR_QUAD_CurrentVersionRun_2184 {
  strings:
    $key_2184 = { 72 eb [2] 56 e5 [2] 7d c9 [2] 53 eb [2] 47 f0 [2] 48 ea [2] 56 f7 [2] 54 f6 [2] 4f f0 [2] 53 f7 [2] 4f d8 }

  condition:
    any of them
}