rule TTP_XOR_QUAD_CurrentVersionRun_a03a {
  strings:
    $key_a03a = { f3 55 [2] d7 5b [2] fc 77 [2] d2 55 [2] c6 4e [2] c9 54 [2] d7 49 [2] d5 48 [2] ce 4e [2] d2 49 [2] ce 66 }

  condition:
    any of them
}