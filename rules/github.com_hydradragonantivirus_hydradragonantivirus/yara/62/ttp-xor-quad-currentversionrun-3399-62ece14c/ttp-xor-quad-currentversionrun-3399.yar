rule TTP_XOR_QUAD_CurrentVersionRun_3399 {
  strings:
    $key_3399 = { 60 f6 [2] 44 f8 [2] 6f d4 [2] 41 f6 [2] 55 ed [2] 5a f7 [2] 44 ea [2] 46 eb [2] 5d ed [2] 41 ea [2] 5d c5 }

  condition:
    any of them
}