rule TTP_XOR_QUAD_CurrentVersionRun_a036 {
  strings:
    $key_a036 = { f3 59 [2] d7 57 [2] fc 7b [2] d2 59 [2] c6 42 [2] c9 58 [2] d7 45 [2] d5 44 [2] ce 42 [2] d2 45 [2] ce 6a }

  condition:
    any of them
}