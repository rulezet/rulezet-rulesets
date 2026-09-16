rule TTP_XOR_QUAD_CurrentVersionRun_aff9 {
  strings:
    $key_aff9 = { fc 96 [2] d8 98 [2] f3 b4 [2] dd 96 [2] c9 8d [2] c6 97 [2] d8 8a [2] da 8b [2] c1 8d [2] dd 8a [2] c1 a5 }

  condition:
    any of them
}