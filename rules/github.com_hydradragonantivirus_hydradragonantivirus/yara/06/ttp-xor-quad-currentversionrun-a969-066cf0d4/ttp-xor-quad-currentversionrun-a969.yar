rule TTP_XOR_QUAD_CurrentVersionRun_a969 {
  strings:
    $key_a969 = { fa 06 [2] de 08 [2] f5 24 [2] db 06 [2] cf 1d [2] c0 07 [2] de 1a [2] dc 1b [2] c7 1d [2] db 1a [2] c7 35 }

  condition:
    any of them
}