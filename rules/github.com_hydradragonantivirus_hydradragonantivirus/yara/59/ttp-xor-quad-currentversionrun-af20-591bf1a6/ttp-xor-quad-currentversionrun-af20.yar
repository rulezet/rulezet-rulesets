rule TTP_XOR_QUAD_CurrentVersionRun_af20 {
  strings:
    $key_af20 = { fc 4f [2] d8 41 [2] f3 6d [2] dd 4f [2] c9 54 [2] c6 4e [2] d8 53 [2] da 52 [2] c1 54 [2] dd 53 [2] c1 7c }

  condition:
    any of them
}