rule TTP_XOR_QUAD_CurrentVersionRun_af0d {
  strings:
    $key_af0d = { fc 62 [2] d8 6c [2] f3 40 [2] dd 62 [2] c9 79 [2] c6 63 [2] d8 7e [2] da 7f [2] c1 79 [2] dd 7e [2] c1 51 }

  condition:
    any of them
}