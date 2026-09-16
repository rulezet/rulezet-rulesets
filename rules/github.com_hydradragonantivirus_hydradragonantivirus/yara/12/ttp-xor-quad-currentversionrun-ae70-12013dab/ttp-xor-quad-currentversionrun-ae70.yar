rule TTP_XOR_QUAD_CurrentVersionRun_ae70 {
  strings:
    $key_ae70 = { fd 1f [2] d9 11 [2] f2 3d [2] dc 1f [2] c8 04 [2] c7 1e [2] d9 03 [2] db 02 [2] c0 04 [2] dc 03 [2] c0 2c }

  condition:
    any of them
}