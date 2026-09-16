rule TTP_XOR_QUAD_CurrentVersionRun_ae5b {
  strings:
    $key_ae5b = { fd 34 [2] d9 3a [2] f2 16 [2] dc 34 [2] c8 2f [2] c7 35 [2] d9 28 [2] db 29 [2] c0 2f [2] dc 28 [2] c0 07 }

  condition:
    any of them
}