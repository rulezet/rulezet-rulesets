rule TTP_XOR_QUAD_CurrentVersionRun_a977 {
  strings:
    $key_a977 = { fa 18 [2] de 16 [2] f5 3a [2] db 18 [2] cf 03 [2] c0 19 [2] de 04 [2] dc 05 [2] c7 03 [2] db 04 [2] c7 2b }

  condition:
    any of them
}