rule TTP_XOR_QUAD_CurrentVersionRun_af3b {
  strings:
    $key_af3b = { fc 54 [2] d8 5a [2] f3 76 [2] dd 54 [2] c9 4f [2] c6 55 [2] d8 48 [2] da 49 [2] c1 4f [2] dd 48 [2] c1 67 }

  condition:
    any of them
}