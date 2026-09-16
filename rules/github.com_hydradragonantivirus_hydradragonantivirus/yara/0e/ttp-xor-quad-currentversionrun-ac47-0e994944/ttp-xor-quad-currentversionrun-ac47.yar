rule TTP_XOR_QUAD_CurrentVersionRun_ac47 {
  strings:
    $key_ac47 = { ff 28 [2] db 26 [2] f0 0a [2] de 28 [2] ca 33 [2] c5 29 [2] db 34 [2] d9 35 [2] c2 33 [2] de 34 [2] c2 1b }

  condition:
    any of them
}