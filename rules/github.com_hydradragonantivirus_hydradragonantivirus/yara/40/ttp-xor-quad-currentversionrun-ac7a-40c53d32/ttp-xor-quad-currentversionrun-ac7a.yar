rule TTP_XOR_QUAD_CurrentVersionRun_ac7a {
  strings:
    $key_ac7a = { ff 15 [2] db 1b [2] f0 37 [2] de 15 [2] ca 0e [2] c5 14 [2] db 09 [2] d9 08 [2] c2 0e [2] de 09 [2] c2 26 }

  condition:
    any of them
}