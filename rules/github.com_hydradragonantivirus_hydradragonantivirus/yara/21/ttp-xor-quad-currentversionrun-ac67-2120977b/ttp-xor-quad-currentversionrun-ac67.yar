rule TTP_XOR_QUAD_CurrentVersionRun_ac67 {
  strings:
    $key_ac67 = { ff 08 [2] db 06 [2] f0 2a [2] de 08 [2] ca 13 [2] c5 09 [2] db 14 [2] d9 15 [2] c2 13 [2] de 14 [2] c2 3b }

  condition:
    any of them
}