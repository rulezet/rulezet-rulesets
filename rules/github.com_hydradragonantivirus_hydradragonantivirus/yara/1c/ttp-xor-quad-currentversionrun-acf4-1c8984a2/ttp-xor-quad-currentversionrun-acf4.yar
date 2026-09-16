rule TTP_XOR_QUAD_CurrentVersionRun_acf4 {
  strings:
    $key_acf4 = { ff 9b [2] db 95 [2] f0 b9 [2] de 9b [2] ca 80 [2] c5 9a [2] db 87 [2] d9 86 [2] c2 80 [2] de 87 [2] c2 a8 }

  condition:
    any of them
}