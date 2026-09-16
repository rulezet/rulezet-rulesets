rule TTP_XOR_QUAD_CurrentVersionRun_a907 {
  strings:
    $key_a907 = { fa 68 [2] de 66 [2] f5 4a [2] db 68 [2] cf 73 [2] c0 69 [2] de 74 [2] dc 75 [2] c7 73 [2] db 74 [2] c7 5b }

  condition:
    any of them
}