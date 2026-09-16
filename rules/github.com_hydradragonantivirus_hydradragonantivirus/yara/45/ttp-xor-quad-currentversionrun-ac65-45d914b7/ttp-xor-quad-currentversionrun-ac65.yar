rule TTP_XOR_QUAD_CurrentVersionRun_ac65 {
  strings:
    $key_ac65 = { ff 0a [2] db 04 [2] f0 28 [2] de 0a [2] ca 11 [2] c5 0b [2] db 16 [2] d9 17 [2] c2 11 [2] de 16 [2] c2 39 }

  condition:
    any of them
}