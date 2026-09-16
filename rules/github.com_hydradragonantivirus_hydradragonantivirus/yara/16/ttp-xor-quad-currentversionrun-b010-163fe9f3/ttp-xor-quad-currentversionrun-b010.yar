rule TTP_XOR_QUAD_CurrentVersionRun_b010 {
  strings:
    $key_b010 = { e3 7f [2] c7 71 [2] ec 5d [2] c2 7f [2] d6 64 [2] d9 7e [2] c7 63 [2] c5 62 [2] de 64 [2] c2 63 [2] de 4c }

  condition:
    any of them
}