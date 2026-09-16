rule TTP_XOR_QUAD_CurrentVersionRun_aff8 {
  strings:
    $key_aff8 = { fc 97 [2] d8 99 [2] f3 b5 [2] dd 97 [2] c9 8c [2] c6 96 [2] d8 8b [2] da 8a [2] c1 8c [2] dd 8b [2] c1 a4 }

  condition:
    any of them
}