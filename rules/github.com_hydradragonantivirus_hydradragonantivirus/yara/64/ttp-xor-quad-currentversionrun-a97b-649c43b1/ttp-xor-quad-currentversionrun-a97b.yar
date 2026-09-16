rule TTP_XOR_QUAD_CurrentVersionRun_a97b {
  strings:
    $key_a97b = { fa 14 [2] de 1a [2] f5 36 [2] db 14 [2] cf 0f [2] c0 15 [2] de 08 [2] dc 09 [2] c7 0f [2] db 08 [2] c7 27 }

  condition:
    any of them
}