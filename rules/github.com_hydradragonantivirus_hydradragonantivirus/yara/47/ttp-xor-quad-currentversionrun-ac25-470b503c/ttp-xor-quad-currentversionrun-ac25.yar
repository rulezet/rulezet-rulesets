rule TTP_XOR_QUAD_CurrentVersionRun_ac25 {
  strings:
    $key_ac25 = { ff 4a [2] db 44 [2] f0 68 [2] de 4a [2] ca 51 [2] c5 4b [2] db 56 [2] d9 57 [2] c2 51 [2] de 56 [2] c2 79 }

  condition:
    any of them
}