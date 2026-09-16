rule TTP_XOR_QUAD_CurrentVersionRun_ac00 {
  strings:
    $key_ac00 = { ff 6f [2] db 61 [2] f0 4d [2] de 6f [2] ca 74 [2] c5 6e [2] db 73 [2] d9 72 [2] c2 74 [2] de 73 [2] c2 5c }

  condition:
    any of them
}