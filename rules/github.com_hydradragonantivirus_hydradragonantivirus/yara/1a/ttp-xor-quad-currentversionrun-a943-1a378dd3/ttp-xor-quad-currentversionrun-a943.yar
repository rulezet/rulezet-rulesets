rule TTP_XOR_QUAD_CurrentVersionRun_a943 {
  strings:
    $key_a943 = { fa 2c [2] de 22 [2] f5 0e [2] db 2c [2] cf 37 [2] c0 2d [2] de 30 [2] dc 31 [2] c7 37 [2] db 30 [2] c7 1f }

  condition:
    any of them
}