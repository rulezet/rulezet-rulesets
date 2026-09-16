rule TTP_XOR_QUAD_CurrentVersionRun_ac72 {
  strings:
    $key_ac72 = { ff 1d [2] db 13 [2] f0 3f [2] de 1d [2] ca 06 [2] c5 1c [2] db 01 [2] d9 00 [2] c2 06 [2] de 01 [2] c2 2e }

  condition:
    any of them
}