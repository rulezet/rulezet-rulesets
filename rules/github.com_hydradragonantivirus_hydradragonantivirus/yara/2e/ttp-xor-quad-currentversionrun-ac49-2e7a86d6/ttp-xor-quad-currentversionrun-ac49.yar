rule TTP_XOR_QUAD_CurrentVersionRun_ac49 {
  strings:
    $key_ac49 = { ff 26 [2] db 28 [2] f0 04 [2] de 26 [2] ca 3d [2] c5 27 [2] db 3a [2] d9 3b [2] c2 3d [2] de 3a [2] c2 15 }

  condition:
    any of them
}