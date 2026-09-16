rule TTP_XOR_QUAD_CurrentVersionRun_2399 {
  strings:
    $key_2399 = { 70 f6 [2] 54 f8 [2] 7f d4 [2] 51 f6 [2] 45 ed [2] 4a f7 [2] 54 ea [2] 56 eb [2] 4d ed [2] 51 ea [2] 4d c5 }

  condition:
    any of them
}