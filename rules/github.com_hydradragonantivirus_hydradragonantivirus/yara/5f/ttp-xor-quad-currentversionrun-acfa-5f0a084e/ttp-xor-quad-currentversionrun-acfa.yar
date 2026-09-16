rule TTP_XOR_QUAD_CurrentVersionRun_acfa {
  strings:
    $key_acfa = { ff 95 [2] db 9b [2] f0 b7 [2] de 95 [2] ca 8e [2] c5 94 [2] db 89 [2] d9 88 [2] c2 8e [2] de 89 [2] c2 a6 }

  condition:
    any of them
}