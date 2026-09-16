rule TTP_XOR_QUAD_CurrentVersionRun_a031 {
  strings:
    $key_a031 = { f3 5e [2] d7 50 [2] fc 7c [2] d2 5e [2] c6 45 [2] c9 5f [2] d7 42 [2] d5 43 [2] ce 45 [2] d2 42 [2] ce 6d }

  condition:
    any of them
}