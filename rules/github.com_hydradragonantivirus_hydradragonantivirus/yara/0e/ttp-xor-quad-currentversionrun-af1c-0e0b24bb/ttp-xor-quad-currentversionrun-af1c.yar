rule TTP_XOR_QUAD_CurrentVersionRun_af1c {
  strings:
    $key_af1c = { fc 73 [2] d8 7d [2] f3 51 [2] dd 73 [2] c9 68 [2] c6 72 [2] d8 6f [2] da 6e [2] c1 68 [2] dd 6f [2] c1 40 }

  condition:
    any of them
}