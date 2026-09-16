rule TTP_XOR_QUAD_CurrentVersionRun_b0ef {
  strings:
    $key_b0ef = { e3 80 [2] c7 8e [2] ec a2 [2] c2 80 [2] d6 9b [2] d9 81 [2] c7 9c [2] c5 9d [2] de 9b [2] c2 9c [2] de b3 }

  condition:
    any of them
}