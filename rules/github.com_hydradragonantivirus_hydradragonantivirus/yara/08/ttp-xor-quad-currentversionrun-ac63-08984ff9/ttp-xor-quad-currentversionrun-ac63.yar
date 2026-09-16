rule TTP_XOR_QUAD_CurrentVersionRun_ac63 {
  strings:
    $key_ac63 = { ff 0c [2] db 02 [2] f0 2e [2] de 0c [2] ca 17 [2] c5 0d [2] db 10 [2] d9 11 [2] c2 17 [2] de 10 [2] c2 3f }

  condition:
    any of them
}