rule TTP_XOR_QUAD_CurrentVersionRun_af31 {
  strings:
    $key_af31 = { fc 5e [2] d8 50 [2] f3 7c [2] dd 5e [2] c9 45 [2] c6 5f [2] d8 42 [2] da 43 [2] c1 45 [2] dd 42 [2] c1 6d }

  condition:
    any of them
}