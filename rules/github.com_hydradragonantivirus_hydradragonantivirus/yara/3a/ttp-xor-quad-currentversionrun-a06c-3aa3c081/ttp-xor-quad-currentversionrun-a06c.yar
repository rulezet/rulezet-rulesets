rule TTP_XOR_QUAD_CurrentVersionRun_a06c {
  strings:
    $key_a06c = { f3 03 [2] d7 0d [2] fc 21 [2] d2 03 [2] c6 18 [2] c9 02 [2] d7 1f [2] d5 1e [2] ce 18 [2] d2 1f [2] ce 30 }

  condition:
    any of them
}