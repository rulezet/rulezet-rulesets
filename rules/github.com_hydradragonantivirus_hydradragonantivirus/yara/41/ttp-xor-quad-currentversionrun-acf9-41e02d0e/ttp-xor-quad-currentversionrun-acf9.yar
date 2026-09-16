rule TTP_XOR_QUAD_CurrentVersionRun_acf9 {
  strings:
    $key_acf9 = { ff 96 [2] db 98 [2] f0 b4 [2] de 96 [2] ca 8d [2] c5 97 [2] db 8a [2] d9 8b [2] c2 8d [2] de 8a [2] c2 a5 }

  condition:
    any of them
}