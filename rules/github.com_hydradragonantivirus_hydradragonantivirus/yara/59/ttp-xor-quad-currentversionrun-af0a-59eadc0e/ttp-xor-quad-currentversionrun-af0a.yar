rule TTP_XOR_QUAD_CurrentVersionRun_af0a {
  strings:
    $key_af0a = { fc 65 [2] d8 6b [2] f3 47 [2] dd 65 [2] c9 7e [2] c6 64 [2] d8 79 [2] da 78 [2] c1 7e [2] dd 79 [2] c1 56 }

  condition:
    any of them
}