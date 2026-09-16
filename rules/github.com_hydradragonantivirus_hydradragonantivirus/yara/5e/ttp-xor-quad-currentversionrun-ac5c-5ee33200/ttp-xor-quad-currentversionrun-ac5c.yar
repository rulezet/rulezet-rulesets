rule TTP_XOR_QUAD_CurrentVersionRun_ac5c {
  strings:
    $key_ac5c = { ff 33 [2] db 3d [2] f0 11 [2] de 33 [2] ca 28 [2] c5 32 [2] db 2f [2] d9 2e [2] c2 28 [2] de 2f [2] c2 00 }

  condition:
    any of them
}