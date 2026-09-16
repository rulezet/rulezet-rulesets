rule TTP_XOR_QUAD_CurrentVersionRun_a979 {
  strings:
    $key_a979 = { fa 16 [2] de 18 [2] f5 34 [2] db 16 [2] cf 0d [2] c0 17 [2] de 0a [2] dc 0b [2] c7 0d [2] db 0a [2] c7 25 }

  condition:
    any of them
}