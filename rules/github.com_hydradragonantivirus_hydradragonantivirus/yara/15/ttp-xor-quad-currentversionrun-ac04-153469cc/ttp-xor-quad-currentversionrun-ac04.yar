rule TTP_XOR_QUAD_CurrentVersionRun_ac04 {
  strings:
    $key_ac04 = { ff 6b [2] db 65 [2] f0 49 [2] de 6b [2] ca 70 [2] c5 6a [2] db 77 [2] d9 76 [2] c2 70 [2] de 77 [2] c2 58 }

  condition:
    any of them
}