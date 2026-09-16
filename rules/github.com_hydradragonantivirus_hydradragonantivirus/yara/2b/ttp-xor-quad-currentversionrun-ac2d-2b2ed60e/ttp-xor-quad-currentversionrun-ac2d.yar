rule TTP_XOR_QUAD_CurrentVersionRun_ac2d {
  strings:
    $key_ac2d = { ff 42 [2] db 4c [2] f0 60 [2] de 42 [2] ca 59 [2] c5 43 [2] db 5e [2] d9 5f [2] c2 59 [2] de 5e [2] c2 71 }

  condition:
    any of them
}