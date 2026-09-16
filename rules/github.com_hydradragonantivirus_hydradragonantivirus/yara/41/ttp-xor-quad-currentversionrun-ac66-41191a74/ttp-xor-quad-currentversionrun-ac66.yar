rule TTP_XOR_QUAD_CurrentVersionRun_ac66 {
  strings:
    $key_ac66 = { ff 09 [2] db 07 [2] f0 2b [2] de 09 [2] ca 12 [2] c5 08 [2] db 15 [2] d9 14 [2] c2 12 [2] de 15 [2] c2 3a }

  condition:
    any of them
}