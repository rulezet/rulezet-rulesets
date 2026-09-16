rule TTP_XOR_QUAD_CurrentVersionRun_affd {
  strings:
    $key_affd = { fc 92 [2] d8 9c [2] f3 b0 [2] dd 92 [2] c9 89 [2] c6 93 [2] d8 8e [2] da 8f [2] c1 89 [2] dd 8e [2] c1 a1 }

  condition:
    any of them
}