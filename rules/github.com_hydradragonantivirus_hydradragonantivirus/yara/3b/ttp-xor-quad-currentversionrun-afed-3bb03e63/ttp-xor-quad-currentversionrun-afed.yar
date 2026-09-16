rule TTP_XOR_QUAD_CurrentVersionRun_afed {
  strings:
    $key_afed = { fc 82 [2] d8 8c [2] f3 a0 [2] dd 82 [2] c9 99 [2] c6 83 [2] d8 9e [2] da 9f [2] c1 99 [2] dd 9e [2] c1 b1 }

  condition:
    any of them
}