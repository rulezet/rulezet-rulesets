rule TTP_XOR_QUAD_CurrentVersionRun_a924 {
  strings:
    $key_a924 = { fa 4b [2] de 45 [2] f5 69 [2] db 4b [2] cf 50 [2] c0 4a [2] de 57 [2] dc 56 [2] c7 50 [2] db 57 [2] c7 78 }

  condition:
    any of them
}