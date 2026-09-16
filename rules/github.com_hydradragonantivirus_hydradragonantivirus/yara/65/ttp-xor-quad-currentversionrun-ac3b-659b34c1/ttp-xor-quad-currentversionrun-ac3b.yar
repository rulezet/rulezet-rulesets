rule TTP_XOR_QUAD_CurrentVersionRun_ac3b {
  strings:
    $key_ac3b = { ff 54 [2] db 5a [2] f0 76 [2] de 54 [2] ca 4f [2] c5 55 [2] db 48 [2] d9 49 [2] c2 4f [2] de 48 [2] c2 67 }

  condition:
    any of them
}