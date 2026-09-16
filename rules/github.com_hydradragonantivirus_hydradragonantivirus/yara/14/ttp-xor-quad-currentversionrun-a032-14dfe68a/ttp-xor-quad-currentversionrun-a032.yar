rule TTP_XOR_QUAD_CurrentVersionRun_a032 {
  strings:
    $key_a032 = { f3 5d [2] d7 53 [2] fc 7f [2] d2 5d [2] c6 46 [2] c9 5c [2] d7 41 [2] d5 40 [2] ce 46 [2] d2 41 [2] ce 6e }

  condition:
    any of them
}