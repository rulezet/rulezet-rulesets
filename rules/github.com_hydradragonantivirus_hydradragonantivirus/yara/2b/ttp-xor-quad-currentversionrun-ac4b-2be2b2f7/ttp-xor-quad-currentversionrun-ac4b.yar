rule TTP_XOR_QUAD_CurrentVersionRun_ac4b {
  strings:
    $key_ac4b = { ff 24 [2] db 2a [2] f0 06 [2] de 24 [2] ca 3f [2] c5 25 [2] db 38 [2] d9 39 [2] c2 3f [2] de 38 [2] c2 17 }

  condition:
    any of them
}