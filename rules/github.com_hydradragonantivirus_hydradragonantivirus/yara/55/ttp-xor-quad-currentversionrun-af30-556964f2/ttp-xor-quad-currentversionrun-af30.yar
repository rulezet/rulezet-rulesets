rule TTP_XOR_QUAD_CurrentVersionRun_af30 {
  strings:
    $key_af30 = { fc 5f [2] d8 51 [2] f3 7d [2] dd 5f [2] c9 44 [2] c6 5e [2] d8 43 [2] da 42 [2] c1 44 [2] dd 43 [2] c1 6c }

  condition:
    any of them
}