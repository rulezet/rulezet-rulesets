rule TTP_XOR_QUAD_CurrentVersionRun_a948 {
  strings:
    $key_a948 = { fa 27 [2] de 29 [2] f5 05 [2] db 27 [2] cf 3c [2] c0 26 [2] de 3b [2] dc 3a [2] c7 3c [2] db 3b [2] c7 14 }

  condition:
    any of them
}