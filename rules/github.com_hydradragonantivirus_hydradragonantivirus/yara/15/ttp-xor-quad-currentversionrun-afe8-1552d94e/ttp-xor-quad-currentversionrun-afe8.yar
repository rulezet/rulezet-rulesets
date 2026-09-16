rule TTP_XOR_QUAD_CurrentVersionRun_afe8 {
  strings:
    $key_afe8 = { fc 87 [2] d8 89 [2] f3 a5 [2] dd 87 [2] c9 9c [2] c6 86 [2] d8 9b [2] da 9a [2] c1 9c [2] dd 9b [2] c1 b4 }

  condition:
    any of them
}