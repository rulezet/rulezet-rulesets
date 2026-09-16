rule TTP_XOR_QUAD_CurrentVersionRun_a00d {
  strings:
    $key_a00d = { f3 62 [2] d7 6c [2] fc 40 [2] d2 62 [2] c6 79 [2] c9 63 [2] d7 7e [2] d5 7f [2] ce 79 [2] d2 7e [2] ce 51 }

  condition:
    any of them
}