rule TTP_XOR_QUAD_CurrentVersionRun_ac53 {
  strings:
    $key_ac53 = { ff 3c [2] db 32 [2] f0 1e [2] de 3c [2] ca 27 [2] c5 3d [2] db 20 [2] d9 21 [2] c2 27 [2] de 20 [2] c2 0f }

  condition:
    any of them
}