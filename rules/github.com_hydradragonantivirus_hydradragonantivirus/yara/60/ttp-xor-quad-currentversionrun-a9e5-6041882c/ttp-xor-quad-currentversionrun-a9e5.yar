rule TTP_XOR_QUAD_CurrentVersionRun_a9e5 {
  strings:
    $key_a9e5 = { fa 8a [2] de 84 [2] f5 a8 [2] db 8a [2] cf 91 [2] c0 8b [2] de 96 [2] dc 97 [2] c7 91 [2] db 96 [2] c7 b9 }

  condition:
    any of them
}