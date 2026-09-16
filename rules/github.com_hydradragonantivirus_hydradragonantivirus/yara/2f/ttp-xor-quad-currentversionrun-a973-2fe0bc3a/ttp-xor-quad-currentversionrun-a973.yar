rule TTP_XOR_QUAD_CurrentVersionRun_a973 {
  strings:
    $key_a973 = { fa 1c [2] de 12 [2] f5 3e [2] db 1c [2] cf 07 [2] c0 1d [2] de 00 [2] dc 01 [2] c7 07 [2] db 00 [2] c7 2f }

  condition:
    any of them
}