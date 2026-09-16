rule TTP_XOR_QUAD_CurrentVersionRun_b099 {
  strings:
    $key_b099 = { e3 f6 [2] c7 f8 [2] ec d4 [2] c2 f6 [2] d6 ed [2] d9 f7 [2] c7 ea [2] c5 eb [2] de ed [2] c2 ea [2] de c5 }

  condition:
    any of them
}