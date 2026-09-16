rule TTP_XOR_QUAD_CurrentVersionRun_ac60 {
  strings:
    $key_ac60 = { ff 0f [2] db 01 [2] f0 2d [2] de 0f [2] ca 14 [2] c5 0e [2] db 13 [2] d9 12 [2] c2 14 [2] de 13 [2] c2 3c }

  condition:
    any of them
}