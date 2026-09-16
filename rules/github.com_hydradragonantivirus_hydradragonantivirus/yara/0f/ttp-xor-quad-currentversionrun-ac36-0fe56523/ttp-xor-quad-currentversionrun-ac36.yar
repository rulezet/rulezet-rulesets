rule TTP_XOR_QUAD_CurrentVersionRun_ac36 {
  strings:
    $key_ac36 = { ff 59 [2] db 57 [2] f0 7b [2] de 59 [2] ca 42 [2] c5 58 [2] db 45 [2] d9 44 [2] c2 42 [2] de 45 [2] c2 6a }

  condition:
    any of them
}