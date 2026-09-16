rule TTP_XOR_QUAD_CurrentVersionRun_ae42 {
  strings:
    $key_ae42 = { fd 2d [2] d9 23 [2] f2 0f [2] dc 2d [2] c8 36 [2] c7 2c [2] d9 31 [2] db 30 [2] c0 36 [2] dc 31 [2] c0 1e }

  condition:
    any of them
}