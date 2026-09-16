rule TTP_XOR_QUAD_CurrentVersionRun_ac03 {
  strings:
    $key_ac03 = { ff 6c [2] db 62 [2] f0 4e [2] de 6c [2] ca 77 [2] c5 6d [2] db 70 [2] d9 71 [2] c2 77 [2] de 70 [2] c2 5f }

  condition:
    any of them
}