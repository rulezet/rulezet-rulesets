rule TTP_XOR_QUAD_CurrentVersionRun_acff {
  strings:
    $key_acff = { ff 90 [2] db 9e [2] f0 b2 [2] de 90 [2] ca 8b [2] c5 91 [2] db 8c [2] d9 8d [2] c2 8b [2] de 8c [2] c2 a3 }

  condition:
    any of them
}