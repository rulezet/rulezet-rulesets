rule TTP_XOR_QUAD_CurrentVersionRun_a7e4 {
  strings:
    $key_a7e4 = { f4 8b [2] d0 85 [2] fb a9 [2] d5 8b [2] c1 90 [2] ce 8a [2] d0 97 [2] d2 96 [2] c9 90 [2] d5 97 [2] c9 b8 }

  condition:
    any of them
}