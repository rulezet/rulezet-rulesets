rule TTP_XOR_QUAD_CurrentVersionRun_af2a {
  strings:
    $key_af2a = { fc 45 [2] d8 4b [2] f3 67 [2] dd 45 [2] c9 5e [2] c6 44 [2] d8 59 [2] da 58 [2] c1 5e [2] dd 59 [2] c1 76 }

  condition:
    any of them
}