rule TTP_XOR_QUAD_CurrentVersionRun_b03a {
  strings:
    $key_b03a = { e3 55 [2] c7 5b [2] ec 77 [2] c2 55 [2] d6 4e [2] d9 54 [2] c7 49 [2] c5 48 [2] de 4e [2] c2 49 [2] de 66 }

  condition:
    any of them
}