rule TTP_XOR_QUAD_CurrentVersionRun_a7c2 {
  strings:
    $key_a7c2 = { f4 ad [2] d0 a3 [2] fb 8f [2] d5 ad [2] c1 b6 [2] ce ac [2] d0 b1 [2] d2 b0 [2] c9 b6 [2] d5 b1 [2] c9 9e }

  condition:
    any of them
}