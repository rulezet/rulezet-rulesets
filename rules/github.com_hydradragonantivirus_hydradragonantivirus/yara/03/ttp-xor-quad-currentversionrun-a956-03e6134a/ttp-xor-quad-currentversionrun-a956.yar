rule TTP_XOR_QUAD_CurrentVersionRun_a956 {
  strings:
    $key_a956 = { fa 39 [2] de 37 [2] f5 1b [2] db 39 [2] cf 22 [2] c0 38 [2] de 25 [2] dc 24 [2] c7 22 [2] db 25 [2] c7 0a }

  condition:
    any of them
}