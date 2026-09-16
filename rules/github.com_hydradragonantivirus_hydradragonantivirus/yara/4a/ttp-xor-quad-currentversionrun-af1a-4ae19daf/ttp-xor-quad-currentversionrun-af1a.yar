rule TTP_XOR_QUAD_CurrentVersionRun_af1a {
  strings:
    $key_af1a = { fc 75 [2] d8 7b [2] f3 57 [2] dd 75 [2] c9 6e [2] c6 74 [2] d8 69 [2] da 68 [2] c1 6e [2] dd 69 [2] c1 46 }

  condition:
    any of them
}