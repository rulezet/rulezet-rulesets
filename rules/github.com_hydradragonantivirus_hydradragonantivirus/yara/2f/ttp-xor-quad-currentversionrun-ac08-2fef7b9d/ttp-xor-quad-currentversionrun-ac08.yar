rule TTP_XOR_QUAD_CurrentVersionRun_ac08 {
  strings:
    $key_ac08 = { ff 67 [2] db 69 [2] f0 45 [2] de 67 [2] ca 7c [2] c5 66 [2] db 7b [2] d9 7a [2] c2 7c [2] de 7b [2] c2 54 }

  condition:
    any of them
}