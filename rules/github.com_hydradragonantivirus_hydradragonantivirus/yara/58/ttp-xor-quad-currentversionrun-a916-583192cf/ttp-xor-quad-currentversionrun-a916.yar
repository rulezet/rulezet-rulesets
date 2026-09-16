rule TTP_XOR_QUAD_CurrentVersionRun_a916 {
  strings:
    $key_a916 = { fa 79 [2] de 77 [2] f5 5b [2] db 79 [2] cf 62 [2] c0 78 [2] de 65 [2] dc 64 [2] c7 62 [2] db 65 [2] c7 4a }

  condition:
    any of them
}