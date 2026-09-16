rule TTP_XOR_QUAD_CurrentVersionRun_a085 {
  strings:
    $key_a085 = { f3 ea [2] d7 e4 [2] fc c8 [2] d2 ea [2] c6 f1 [2] c9 eb [2] d7 f6 [2] d5 f7 [2] ce f1 [2] d2 f6 [2] ce d9 }

  condition:
    any of them
}