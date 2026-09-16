rule TTP_XOR_QUAD_CurrentVersionRun_a9f7 {
  strings:
    $key_a9f7 = { fa 98 [2] de 96 [2] f5 ba [2] db 98 [2] cf 83 [2] c0 99 [2] de 84 [2] dc 85 [2] c7 83 [2] db 84 [2] c7 ab }

  condition:
    any of them
}