rule TTP_XOR_QUAD_CurrentVersionRun_b003 {
  strings:
    $key_b003 = { e3 6c [2] c7 62 [2] ec 4e [2] c2 6c [2] d6 77 [2] d9 6d [2] c7 70 [2] c5 71 [2] de 77 [2] c2 70 [2] de 5f }

  condition:
    any of them
}