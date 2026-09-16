rule TTP_XOR_QUAD_CurrentVersionRun_af6f {
  strings:
    $key_af6f = { fc 00 [2] d8 0e [2] f3 22 [2] dd 00 [2] c9 1b [2] c6 01 [2] d8 1c [2] da 1d [2] c1 1b [2] dd 1c [2] c1 33 }

  condition:
    any of them
}