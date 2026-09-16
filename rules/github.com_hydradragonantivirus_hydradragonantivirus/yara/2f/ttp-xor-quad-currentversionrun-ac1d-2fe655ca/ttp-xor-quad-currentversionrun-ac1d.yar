rule TTP_XOR_QUAD_CurrentVersionRun_ac1d {
  strings:
    $key_ac1d = { ff 72 [2] db 7c [2] f0 50 [2] de 72 [2] ca 69 [2] c5 73 [2] db 6e [2] d9 6f [2] c2 69 [2] de 6e [2] c2 41 }

  condition:
    any of them
}