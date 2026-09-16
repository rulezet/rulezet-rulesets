rule TTP_XOR_QUAD_CurrentVersionRun_afea {
  strings:
    $key_afea = { fc 85 [2] d8 8b [2] f3 a7 [2] dd 85 [2] c9 9e [2] c6 84 [2] d8 99 [2] da 98 [2] c1 9e [2] dd 99 [2] c1 b6 }

  condition:
    any of them
}