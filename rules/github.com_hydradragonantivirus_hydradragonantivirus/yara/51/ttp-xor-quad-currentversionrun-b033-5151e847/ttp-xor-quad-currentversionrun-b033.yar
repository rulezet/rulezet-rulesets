rule TTP_XOR_QUAD_CurrentVersionRun_b033 {
  strings:
    $key_b033 = { e3 5c [2] c7 52 [2] ec 7e [2] c2 5c [2] d6 47 [2] d9 5d [2] c7 40 [2] c5 41 [2] de 47 [2] c2 40 [2] de 6f }

  condition:
    any of them
}