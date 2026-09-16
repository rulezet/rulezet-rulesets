rule TTP_XOR_QUAD_CurrentVersionRun_ac3e {
  strings:
    $key_ac3e = { ff 51 [2] db 5f [2] f0 73 [2] de 51 [2] ca 4a [2] c5 50 [2] db 4d [2] d9 4c [2] c2 4a [2] de 4d [2] c2 62 }

  condition:
    any of them
}