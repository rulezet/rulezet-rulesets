rule TTP_XOR_QUAD_CurrentVersionRun_ac75 {
  strings:
    $key_ac75 = { ff 1a [2] db 14 [2] f0 38 [2] de 1a [2] ca 01 [2] c5 1b [2] db 06 [2] d9 07 [2] c2 01 [2] de 06 [2] c2 29 }

  condition:
    any of them
}