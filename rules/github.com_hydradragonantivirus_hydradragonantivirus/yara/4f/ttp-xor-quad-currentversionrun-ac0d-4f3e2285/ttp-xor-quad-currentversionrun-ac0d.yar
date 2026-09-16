rule TTP_XOR_QUAD_CurrentVersionRun_ac0d {
  strings:
    $key_ac0d = { ff 62 [2] db 6c [2] f0 40 [2] de 62 [2] ca 79 [2] c5 63 [2] db 7e [2] d9 7f [2] c2 79 [2] de 7e [2] c2 51 }

  condition:
    any of them
}