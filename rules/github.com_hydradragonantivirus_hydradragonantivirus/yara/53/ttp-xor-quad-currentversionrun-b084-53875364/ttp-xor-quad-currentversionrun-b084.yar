rule TTP_XOR_QUAD_CurrentVersionRun_b084 {
  strings:
    $key_b084 = { e3 eb [2] c7 e5 [2] ec c9 [2] c2 eb [2] d6 f0 [2] d9 ea [2] c7 f7 [2] c5 f6 [2] de f0 [2] c2 f7 [2] de d8 }

  condition:
    any of them
}