rule TTP_XOR_QUAD_CurrentVersionRun_b02a {
  strings:
    $key_b02a = { e3 45 [2] c7 4b [2] ec 67 [2] c2 45 [2] d6 5e [2] d9 44 [2] c7 59 [2] c5 58 [2] de 5e [2] c2 59 [2] de 76 }

  condition:
    any of them
}