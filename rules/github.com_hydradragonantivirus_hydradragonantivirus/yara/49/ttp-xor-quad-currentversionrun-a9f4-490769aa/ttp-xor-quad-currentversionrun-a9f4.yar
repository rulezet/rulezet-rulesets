rule TTP_XOR_QUAD_CurrentVersionRun_a9f4 {
  strings:
    $key_a9f4 = { fa 9b [2] de 95 [2] f5 b9 [2] db 9b [2] cf 80 [2] c0 9a [2] de 87 [2] dc 86 [2] c7 80 [2] db 87 [2] c7 a8 }

  condition:
    any of them
}