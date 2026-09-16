rule TTP_XOR_QUAD_CurrentVersionRun_a946 {
  strings:
    $key_a946 = { fa 29 [2] de 27 [2] f5 0b [2] db 29 [2] cf 32 [2] c0 28 [2] de 35 [2] dc 34 [2] c7 32 [2] db 35 [2] c7 1a }

  condition:
    any of them
}