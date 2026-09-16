rule TTP_XOR_QUAD_CurrentVersionRun_ae6e {
  strings:
    $key_ae6e = { fd 01 [2] d9 0f [2] f2 23 [2] dc 01 [2] c8 1a [2] c7 00 [2] d9 1d [2] db 1c [2] c0 1a [2] dc 1d [2] c0 32 }

  condition:
    any of them
}