rule TTP_XOR_QUAD_CurrentVersionRun_af3e {
  strings:
    $key_af3e = { fc 51 [2] d8 5f [2] f3 73 [2] dd 51 [2] c9 4a [2] c6 50 [2] d8 4d [2] da 4c [2] c1 4a [2] dd 4d [2] c1 62 }

  condition:
    any of them
}