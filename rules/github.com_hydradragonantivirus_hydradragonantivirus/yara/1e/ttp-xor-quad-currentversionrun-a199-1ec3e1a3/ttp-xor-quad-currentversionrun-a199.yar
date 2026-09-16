rule TTP_XOR_QUAD_CurrentVersionRun_a199 {
  strings:
    $key_a199 = { f2 f6 [2] d6 f8 [2] fd d4 [2] d3 f6 [2] c7 ed [2] c8 f7 [2] d6 ea [2] d4 eb [2] cf ed [2] d3 ea [2] cf c5 }

  condition:
    any of them
}