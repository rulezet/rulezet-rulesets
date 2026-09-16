rule TTP_XOR_QUAD_CurrentVersionRun_a970 {
  strings:
    $key_a970 = { fa 1f [2] de 11 [2] f5 3d [2] db 1f [2] cf 04 [2] c0 1e [2] de 03 [2] dc 02 [2] c7 04 [2] db 03 [2] c7 2c }

  condition:
    any of them
}