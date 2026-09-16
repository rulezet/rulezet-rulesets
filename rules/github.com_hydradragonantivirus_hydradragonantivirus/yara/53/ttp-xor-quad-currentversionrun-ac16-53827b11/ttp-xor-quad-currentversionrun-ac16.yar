rule TTP_XOR_QUAD_CurrentVersionRun_ac16 {
  strings:
    $key_ac16 = { ff 79 [2] db 77 [2] f0 5b [2] de 79 [2] ca 62 [2] c5 78 [2] db 65 [2] d9 64 [2] c2 62 [2] de 65 [2] c2 4a }

  condition:
    any of them
}