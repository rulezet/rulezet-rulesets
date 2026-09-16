rule TTP_XOR_QUAD_CurrentVersionRun_a958 {
  strings:
    $key_a958 = { fa 37 [2] de 39 [2] f5 15 [2] db 37 [2] cf 2c [2] c0 36 [2] de 2b [2] dc 2a [2] c7 2c [2] db 2b [2] c7 04 }

  condition:
    any of them
}