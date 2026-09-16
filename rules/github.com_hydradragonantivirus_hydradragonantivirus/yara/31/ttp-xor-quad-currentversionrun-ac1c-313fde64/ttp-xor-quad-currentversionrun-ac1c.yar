rule TTP_XOR_QUAD_CurrentVersionRun_ac1c {
  strings:
    $key_ac1c = { ff 73 [2] db 7d [2] f0 51 [2] de 73 [2] ca 68 [2] c5 72 [2] db 6f [2] d9 6e [2] c2 68 [2] de 6f [2] c2 40 }

  condition:
    any of them
}