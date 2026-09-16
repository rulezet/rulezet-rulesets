rule TTP_XOR_QUAD_CurrentVersionRun_ac42 {
  strings:
    $key_ac42 = { ff 2d [2] db 23 [2] f0 0f [2] de 2d [2] ca 36 [2] c5 2c [2] db 31 [2] d9 30 [2] c2 36 [2] de 31 [2] c2 1e }

  condition:
    any of them
}