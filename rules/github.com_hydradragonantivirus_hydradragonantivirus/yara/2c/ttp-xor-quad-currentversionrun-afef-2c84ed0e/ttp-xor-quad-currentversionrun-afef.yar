rule TTP_XOR_QUAD_CurrentVersionRun_afef {
  strings:
    $key_afef = { fc 80 [2] d8 8e [2] f3 a2 [2] dd 80 [2] c9 9b [2] c6 81 [2] d8 9c [2] da 9d [2] c1 9b [2] dd 9c [2] c1 b3 }

  condition:
    any of them
}