rule TTP_XOR_QUAD_CurrentVersionRun_acf5 {
  strings:
    $key_acf5 = { ff 9a [2] db 94 [2] f0 b8 [2] de 9a [2] ca 81 [2] c5 9b [2] db 86 [2] d9 87 [2] c2 81 [2] de 86 [2] c2 a9 }

  condition:
    any of them
}