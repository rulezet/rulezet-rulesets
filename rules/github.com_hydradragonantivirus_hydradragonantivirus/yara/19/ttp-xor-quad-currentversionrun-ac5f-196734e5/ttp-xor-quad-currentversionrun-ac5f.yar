rule TTP_XOR_QUAD_CurrentVersionRun_ac5f {
  strings:
    $key_ac5f = { ff 30 [2] db 3e [2] f0 12 [2] de 30 [2] ca 2b [2] c5 31 [2] db 2c [2] d9 2d [2] c2 2b [2] de 2c [2] c2 03 }

  condition:
    any of them
}