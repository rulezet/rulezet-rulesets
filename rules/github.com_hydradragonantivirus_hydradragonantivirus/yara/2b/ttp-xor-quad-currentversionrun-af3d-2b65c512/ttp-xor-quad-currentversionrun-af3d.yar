rule TTP_XOR_QUAD_CurrentVersionRun_af3d {
  strings:
    $key_af3d = { fc 52 [2] d8 5c [2] f3 70 [2] dd 52 [2] c9 49 [2] c6 53 [2] d8 4e [2] da 4f [2] c1 49 [2] dd 4e [2] c1 61 }

  condition:
    any of them
}