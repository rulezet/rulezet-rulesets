rule TTP_XOR_QUAD_CurrentVersionRun_a909 {
  strings:
    $key_a909 = { fa 66 [2] de 68 [2] f5 44 [2] db 66 [2] cf 7d [2] c0 67 [2] de 7a [2] dc 7b [2] c7 7d [2] db 7a [2] c7 55 }

  condition:
    any of them
}