rule TTP_XOR_QUAD_CurrentVersionRun_ac40 {
  strings:
    $key_ac40 = { ff 2f [2] db 21 [2] f0 0d [2] de 2f [2] ca 34 [2] c5 2e [2] db 33 [2] d9 32 [2] c2 34 [2] de 33 [2] c2 1c }

  condition:
    any of them
}