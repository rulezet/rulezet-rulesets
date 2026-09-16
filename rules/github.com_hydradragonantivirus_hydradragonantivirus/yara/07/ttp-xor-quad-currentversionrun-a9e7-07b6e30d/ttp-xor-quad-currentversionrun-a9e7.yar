rule TTP_XOR_QUAD_CurrentVersionRun_a9e7 {
  strings:
    $key_a9e7 = { fa 88 [2] de 86 [2] f5 aa [2] db 88 [2] cf 93 [2] c0 89 [2] de 94 [2] dc 95 [2] c7 93 [2] db 94 [2] c7 bb }

  condition:
    any of them
}