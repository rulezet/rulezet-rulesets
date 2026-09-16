rule TTP_XOR_QUAD_CurrentVersionRun_af6a {
  strings:
    $key_af6a = { fc 05 [2] d8 0b [2] f3 27 [2] dd 05 [2] c9 1e [2] c6 04 [2] d8 19 [2] da 18 [2] c1 1e [2] dd 19 [2] c1 36 }

  condition:
    any of them
}