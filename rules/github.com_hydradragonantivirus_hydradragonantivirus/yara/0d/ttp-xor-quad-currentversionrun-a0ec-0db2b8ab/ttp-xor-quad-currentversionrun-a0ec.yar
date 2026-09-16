rule TTP_XOR_QUAD_CurrentVersionRun_a0ec {
  strings:
    $key_a0ec = { f3 83 [2] d7 8d [2] fc a1 [2] d2 83 [2] c6 98 [2] c9 82 [2] d7 9f [2] d5 9e [2] ce 98 [2] d2 9f [2] ce b0 }

  condition:
    any of them
}