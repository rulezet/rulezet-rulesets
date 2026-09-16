rule TTP_XOR_QUAD_CurrentVersionRun_ac79 {
  strings:
    $key_ac79 = { ff 16 [2] db 18 [2] f0 34 [2] de 16 [2] ca 0d [2] c5 17 [2] db 0a [2] d9 0b [2] c2 0d [2] de 0a [2] c2 25 }

  condition:
    any of them
}