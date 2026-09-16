rule TTP_XOR_QUAD_CurrentVersionRun_ac59 {
  strings:
    $key_ac59 = { ff 36 [2] db 38 [2] f0 14 [2] de 36 [2] ca 2d [2] c5 37 [2] db 2a [2] d9 2b [2] c2 2d [2] de 2a [2] c2 05 }

  condition:
    any of them
}