rule TTP_XOR_QUAD_CurrentVersionRun_acf8 {
  strings:
    $key_acf8 = { ff 97 [2] db 99 [2] f0 b5 [2] de 97 [2] ca 8c [2] c5 96 [2] db 8b [2] d9 8a [2] c2 8c [2] de 8b [2] c2 a4 }

  condition:
    any of them
}