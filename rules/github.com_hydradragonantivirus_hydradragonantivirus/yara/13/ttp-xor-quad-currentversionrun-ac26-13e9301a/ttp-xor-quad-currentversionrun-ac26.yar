rule TTP_XOR_QUAD_CurrentVersionRun_ac26 {
  strings:
    $key_ac26 = { ff 49 [2] db 47 [2] f0 6b [2] de 49 [2] ca 52 [2] c5 48 [2] db 55 [2] d9 54 [2] c2 52 [2] de 55 [2] c2 7a }

  condition:
    any of them
}