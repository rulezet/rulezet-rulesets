rule TTP_XOR_QUAD_CurrentVersionRun_af1e {
  strings:
    $key_af1e = { fc 71 [2] d8 7f [2] f3 53 [2] dd 71 [2] c9 6a [2] c6 70 [2] d8 6d [2] da 6c [2] c1 6a [2] dd 6d [2] c1 42 }

  condition:
    any of them
}