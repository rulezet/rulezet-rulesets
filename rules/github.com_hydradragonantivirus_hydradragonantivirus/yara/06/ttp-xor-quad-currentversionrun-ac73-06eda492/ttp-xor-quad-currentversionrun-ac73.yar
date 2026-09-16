rule TTP_XOR_QUAD_CurrentVersionRun_ac73 {
  strings:
    $key_ac73 = { ff 1c [2] db 12 [2] f0 3e [2] de 1c [2] ca 07 [2] c5 1d [2] db 00 [2] d9 01 [2] c2 07 [2] de 00 [2] c2 2f }

  condition:
    any of them
}