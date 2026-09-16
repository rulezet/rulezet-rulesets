rule TTP_XOR_QUAD_CurrentVersionRun_a084 {
  strings:
    $key_a084 = { f3 eb [2] d7 e5 [2] fc c9 [2] d2 eb [2] c6 f0 [2] c9 ea [2] d7 f7 [2] d5 f6 [2] ce f0 [2] d2 f7 [2] ce d8 }

  condition:
    any of them
}