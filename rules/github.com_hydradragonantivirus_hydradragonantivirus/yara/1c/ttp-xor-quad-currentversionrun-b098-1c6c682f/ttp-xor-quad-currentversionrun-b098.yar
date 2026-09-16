rule TTP_XOR_QUAD_CurrentVersionRun_b098 {
  strings:
    $key_b098 = { e3 f7 [2] c7 f9 [2] ec d5 [2] c2 f7 [2] d6 ec [2] d9 f6 [2] c7 eb [2] c5 ea [2] de ec [2] c2 eb [2] de c4 }

  condition:
    any of them
}