rule TTP_XOR_QUAD_CurrentVersionRun_ace8 {
  strings:
    $key_ace8 = { ff 87 [2] db 89 [2] f0 a5 [2] de 87 [2] ca 9c [2] c5 86 [2] db 9b [2] d9 9a [2] c2 9c [2] de 9b [2] c2 b4 }

  condition:
    any of them
}