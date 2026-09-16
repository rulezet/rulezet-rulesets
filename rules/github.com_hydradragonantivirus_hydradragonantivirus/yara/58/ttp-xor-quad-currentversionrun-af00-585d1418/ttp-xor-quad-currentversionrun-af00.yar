rule TTP_XOR_QUAD_CurrentVersionRun_af00 {
  strings:
    $key_af00 = { fc 6f [2] d8 61 [2] f3 4d [2] dd 6f [2] c9 74 [2] c6 6e [2] d8 73 [2] da 72 [2] c1 74 [2] dd 73 [2] c1 5c }

  condition:
    any of them
}