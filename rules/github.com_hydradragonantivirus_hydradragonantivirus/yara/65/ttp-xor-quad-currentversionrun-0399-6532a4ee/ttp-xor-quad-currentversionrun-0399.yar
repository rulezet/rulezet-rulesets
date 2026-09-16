rule TTP_XOR_QUAD_CurrentVersionRun_0399 {
  strings:
    $key_0399 = { 50 f6 [2] 74 f8 [2] 5f d4 [2] 71 f6 [2] 65 ed [2] 6a f7 [2] 74 ea [2] 76 eb [2] 6d ed [2] 71 ea [2] 6d c5 }

  condition:
    any of them
}