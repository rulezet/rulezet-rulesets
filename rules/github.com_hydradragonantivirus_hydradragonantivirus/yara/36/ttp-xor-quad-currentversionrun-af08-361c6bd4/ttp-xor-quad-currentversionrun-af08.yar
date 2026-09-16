rule TTP_XOR_QUAD_CurrentVersionRun_af08 {
  strings:
    $key_af08 = { fc 67 [2] d8 69 [2] f3 45 [2] dd 67 [2] c9 7c [2] c6 66 [2] d8 7b [2] da 7a [2] c1 7c [2] dd 7b [2] c1 54 }

  condition:
    any of them
}