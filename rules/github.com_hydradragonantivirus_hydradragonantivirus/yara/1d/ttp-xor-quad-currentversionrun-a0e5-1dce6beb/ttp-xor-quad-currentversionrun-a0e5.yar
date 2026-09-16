rule TTP_XOR_QUAD_CurrentVersionRun_a0e5 {
  strings:
    $key_a0e5 = { f3 8a [2] d7 84 [2] fc a8 [2] d2 8a [2] c6 91 [2] c9 8b [2] d7 96 [2] d5 97 [2] ce 91 [2] d2 96 [2] ce b9 }

  condition:
    any of them
}