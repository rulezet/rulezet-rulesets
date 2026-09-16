rule TTP_XOR_QUAD_CurrentVersionRun_b023 {
  strings:
    $key_b023 = { e3 4c [2] c7 42 [2] ec 6e [2] c2 4c [2] d6 57 [2] d9 4d [2] c7 50 [2] c5 51 [2] de 57 [2] c2 50 [2] de 7f }

  condition:
    any of them
}