rule TTP_XOR_QUAD_CurrentVersionRun_b050 {
  strings:
    $key_b050 = { e3 3f [2] c7 31 [2] ec 1d [2] c2 3f [2] d6 24 [2] d9 3e [2] c7 23 [2] c5 22 [2] de 24 [2] c2 23 [2] de 0c }

  condition:
    any of them
}