rule TTP_XOR_QUAD_CurrentVersionRun_ac74 {
  strings:
    $key_ac74 = { ff 1b [2] db 15 [2] f0 39 [2] de 1b [2] ca 00 [2] c5 1a [2] db 07 [2] d9 06 [2] c2 00 [2] de 07 [2] c2 28 }

  condition:
    any of them
}