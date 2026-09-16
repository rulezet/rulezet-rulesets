rule TTP_XOR_QUAD_CurrentVersionRun_ac2a {
  strings:
    $key_ac2a = { ff 45 [2] db 4b [2] f0 67 [2] de 45 [2] ca 5e [2] c5 44 [2] db 59 [2] d9 58 [2] c2 5e [2] de 59 [2] c2 76 }

  condition:
    any of them
}