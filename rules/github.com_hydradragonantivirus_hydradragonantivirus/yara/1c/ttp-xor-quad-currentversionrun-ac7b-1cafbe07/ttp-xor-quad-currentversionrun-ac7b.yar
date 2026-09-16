rule TTP_XOR_QUAD_CurrentVersionRun_ac7b {
  strings:
    $key_ac7b = { ff 14 [2] db 1a [2] f0 36 [2] de 14 [2] ca 0f [2] c5 15 [2] db 08 [2] d9 09 [2] c2 0f [2] de 08 [2] c2 27 }

  condition:
    any of them
}