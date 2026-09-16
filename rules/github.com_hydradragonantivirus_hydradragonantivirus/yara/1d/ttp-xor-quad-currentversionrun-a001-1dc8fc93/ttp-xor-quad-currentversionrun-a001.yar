rule TTP_XOR_QUAD_CurrentVersionRun_a001 {
  strings:
    $key_a001 = { f3 6e [2] d7 60 [2] fc 4c [2] d2 6e [2] c6 75 [2] c9 6f [2] d7 72 [2] d5 73 [2] ce 75 [2] d2 72 [2] ce 5d }

  condition:
    any of them
}