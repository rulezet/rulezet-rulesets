rule TTP_XOR_QUAD_CurrentVersionRun_ac19 {
  strings:
    $key_ac19 = { ff 76 [2] db 78 [2] f0 54 [2] de 76 [2] ca 6d [2] c5 77 [2] db 6a [2] d9 6b [2] c2 6d [2] de 6a [2] c2 45 }

  condition:
    any of them
}