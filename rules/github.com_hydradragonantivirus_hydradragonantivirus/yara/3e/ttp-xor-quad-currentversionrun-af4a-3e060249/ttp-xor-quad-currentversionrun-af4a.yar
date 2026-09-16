rule TTP_XOR_QUAD_CurrentVersionRun_af4a {
  strings:
    $key_af4a = { fc 25 [2] d8 2b [2] f3 07 [2] dd 25 [2] c9 3e [2] c6 24 [2] d8 39 [2] da 38 [2] c1 3e [2] dd 39 [2] c1 16 }

  condition:
    any of them
}