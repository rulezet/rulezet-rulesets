rule TTP_XOR_QUAD_CurrentVersionRun_af3a {
  strings:
    $key_af3a = { fc 55 [2] d8 5b [2] f3 77 [2] dd 55 [2] c9 4e [2] c6 54 [2] d8 49 [2] da 48 [2] c1 4e [2] dd 49 [2] c1 66 }

  condition:
    any of them
}