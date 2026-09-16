rule TTP_XOR_QUAD_CurrentVersionRun_a0c2 {
  strings:
    $key_a0c2 = { f3 ad [2] d7 a3 [2] fc 8f [2] d2 ad [2] c6 b6 [2] c9 ac [2] d7 b1 [2] d5 b0 [2] ce b6 [2] d2 b1 [2] ce 9e }

  condition:
    any of them
}