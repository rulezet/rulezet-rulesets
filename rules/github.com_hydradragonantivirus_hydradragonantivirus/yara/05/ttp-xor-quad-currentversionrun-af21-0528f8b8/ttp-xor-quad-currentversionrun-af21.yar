rule TTP_XOR_QUAD_CurrentVersionRun_af21 {
  strings:
    $key_af21 = { fc 4e [2] d8 40 [2] f3 6c [2] dd 4e [2] c9 55 [2] c6 4f [2] d8 52 [2] da 53 [2] c1 55 [2] dd 52 [2] c1 7d }

  condition:
    any of them
}