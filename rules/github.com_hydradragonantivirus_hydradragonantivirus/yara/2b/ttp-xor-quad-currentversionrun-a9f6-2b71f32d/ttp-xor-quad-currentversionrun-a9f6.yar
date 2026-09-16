rule TTP_XOR_QUAD_CurrentVersionRun_a9f6 {
  strings:
    $key_a9f6 = { fa 99 [2] de 97 [2] f5 bb [2] db 99 [2] cf 82 [2] c0 98 [2] de 85 [2] dc 84 [2] c7 82 [2] db 85 [2] c7 aa }

  condition:
    any of them
}