rule TTP_XOR_QUAD_CurrentVersionRun_a798 {
  strings:
    $key_a798 = { f4 f7 [2] d0 f9 [2] fb d5 [2] d5 f7 [2] c1 ec [2] ce f6 [2] d0 eb [2] d2 ea [2] c9 ec [2] d5 eb [2] c9 c4 }

  condition:
    any of them
}