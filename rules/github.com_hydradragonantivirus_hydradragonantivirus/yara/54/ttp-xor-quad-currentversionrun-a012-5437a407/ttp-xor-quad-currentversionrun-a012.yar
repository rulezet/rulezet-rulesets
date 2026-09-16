rule TTP_XOR_QUAD_CurrentVersionRun_a012 {
  strings:
    $key_a012 = { f3 7d [2] d7 73 [2] fc 5f [2] d2 7d [2] c6 66 [2] c9 7c [2] d7 61 [2] d5 60 [2] ce 66 [2] d2 61 [2] ce 4e }

  condition:
    any of them
}