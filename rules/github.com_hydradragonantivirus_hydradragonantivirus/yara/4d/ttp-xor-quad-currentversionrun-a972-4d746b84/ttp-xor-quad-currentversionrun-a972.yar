rule TTP_XOR_QUAD_CurrentVersionRun_a972 {
  strings:
    $key_a972 = { fa 1d [2] de 13 [2] f5 3f [2] db 1d [2] cf 06 [2] c0 1c [2] de 01 [2] dc 00 [2] c7 06 [2] db 01 [2] c7 2e }

  condition:
    any of them
}