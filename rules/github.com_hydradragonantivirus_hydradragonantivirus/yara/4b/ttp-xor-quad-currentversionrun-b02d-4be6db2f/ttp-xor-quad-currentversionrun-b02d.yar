rule TTP_XOR_QUAD_CurrentVersionRun_b02d {
  strings:
    $key_b02d = { e3 42 [2] c7 4c [2] ec 60 [2] c2 42 [2] d6 59 [2] d9 43 [2] c7 5e [2] c5 5f [2] de 59 [2] c2 5e [2] de 71 }

  condition:
    any of them
}