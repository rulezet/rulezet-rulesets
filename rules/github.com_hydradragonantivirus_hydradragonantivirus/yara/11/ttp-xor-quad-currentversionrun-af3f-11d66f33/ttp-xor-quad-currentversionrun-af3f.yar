rule TTP_XOR_QUAD_CurrentVersionRun_af3f {
  strings:
    $key_af3f = { fc 50 [2] d8 5e [2] f3 72 [2] dd 50 [2] c9 4b [2] c6 51 [2] d8 4c [2] da 4d [2] c1 4b [2] dd 4c [2] c1 63 }

  condition:
    any of them
}