rule TTP_XOR_QUAD_CurrentVersionRun_af6e {
  strings:
    $key_af6e = { fc 01 [2] d8 0f [2] f3 23 [2] dd 01 [2] c9 1a [2] c6 00 [2] d8 1d [2] da 1c [2] c1 1a [2] dd 1d [2] c1 32 }

  condition:
    any of them
}