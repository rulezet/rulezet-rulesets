rule TTP_XOR_QUAD_CurrentVersionRun_a97c {
  strings:
    $key_a97c = { fa 13 [2] de 1d [2] f5 31 [2] db 13 [2] cf 08 [2] c0 12 [2] de 0f [2] dc 0e [2] c7 08 [2] db 0f [2] c7 20 }

  condition:
    any of them
}