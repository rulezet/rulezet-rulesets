rule TTP_XOR_QUAD_CurrentVersionRun_a961 {
  strings:
    $key_a961 = { fa 0e [2] de 00 [2] f5 2c [2] db 0e [2] cf 15 [2] c0 0f [2] de 12 [2] dc 13 [2] c7 15 [2] db 12 [2] c7 3d }

  condition:
    any of them
}