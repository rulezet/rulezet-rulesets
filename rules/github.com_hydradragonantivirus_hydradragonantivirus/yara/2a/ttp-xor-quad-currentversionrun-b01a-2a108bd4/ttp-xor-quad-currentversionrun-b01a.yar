rule TTP_XOR_QUAD_CurrentVersionRun_b01a {
  strings:
    $key_b01a = { e3 75 [2] c7 7b [2] ec 57 [2] c2 75 [2] d6 6e [2] d9 74 [2] c7 69 [2] c5 68 [2] de 6e [2] c2 69 [2] de 46 }

  condition:
    any of them
}