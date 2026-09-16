rule TTP_XOR_QUAD_CurrentVersionRun_af11 {
  strings:
    $key_af11 = { fc 7e [2] d8 70 [2] f3 5c [2] dd 7e [2] c9 65 [2] c6 7f [2] d8 62 [2] da 63 [2] c1 65 [2] dd 62 [2] c1 4d }

  condition:
    any of them
}