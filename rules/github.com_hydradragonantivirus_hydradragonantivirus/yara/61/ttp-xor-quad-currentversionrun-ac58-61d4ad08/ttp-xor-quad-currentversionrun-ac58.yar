rule TTP_XOR_QUAD_CurrentVersionRun_ac58 {
  strings:
    $key_ac58 = { ff 37 [2] db 39 [2] f0 15 [2] de 37 [2] ca 2c [2] c5 36 [2] db 2b [2] d9 2a [2] c2 2c [2] de 2b [2] c2 04 }

  condition:
    any of them
}