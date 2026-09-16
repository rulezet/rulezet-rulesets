rule TTP_XOR_QUAD_CurrentVersionRun_a95f {
  strings:
    $key_a95f = { fa 30 [2] de 3e [2] f5 12 [2] db 30 [2] cf 2b [2] c0 31 [2] de 2c [2] dc 2d [2] c7 2b [2] db 2c [2] c7 03 }

  condition:
    any of them
}