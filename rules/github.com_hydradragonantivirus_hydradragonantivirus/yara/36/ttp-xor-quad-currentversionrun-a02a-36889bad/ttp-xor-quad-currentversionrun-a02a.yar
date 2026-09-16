rule TTP_XOR_QUAD_CurrentVersionRun_a02a {
  strings:
    $key_a02a = { f3 45 [2] d7 4b [2] fc 67 [2] d2 45 [2] c6 5e [2] c9 44 [2] d7 59 [2] d5 58 [2] ce 5e [2] d2 59 [2] ce 76 }

  condition:
    any of them
}