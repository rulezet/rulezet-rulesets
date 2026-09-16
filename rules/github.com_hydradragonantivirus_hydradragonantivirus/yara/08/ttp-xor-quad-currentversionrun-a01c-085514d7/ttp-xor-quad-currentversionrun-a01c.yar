rule TTP_XOR_QUAD_CurrentVersionRun_a01c {
  strings:
    $key_a01c = { f3 73 [2] d7 7d [2] fc 51 [2] d2 73 [2] c6 68 [2] c9 72 [2] d7 6f [2] d5 6e [2] ce 68 [2] d2 6f [2] ce 40 }

  condition:
    any of them
}