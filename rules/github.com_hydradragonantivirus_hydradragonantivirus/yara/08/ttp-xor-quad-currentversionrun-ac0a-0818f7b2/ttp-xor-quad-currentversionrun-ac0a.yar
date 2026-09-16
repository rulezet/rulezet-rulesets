rule TTP_XOR_QUAD_CurrentVersionRun_ac0a {
  strings:
    $key_ac0a = { ff 65 [2] db 6b [2] f0 47 [2] de 65 [2] ca 7e [2] c5 64 [2] db 79 [2] d9 78 [2] c2 7e [2] de 79 [2] c2 56 }

  condition:
    any of them
}