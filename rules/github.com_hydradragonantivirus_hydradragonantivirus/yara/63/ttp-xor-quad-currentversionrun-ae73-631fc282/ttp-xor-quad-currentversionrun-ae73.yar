rule TTP_XOR_QUAD_CurrentVersionRun_ae73 {
  strings:
    $key_ae73 = { fd 1c [2] d9 12 [2] f2 3e [2] dc 1c [2] c8 07 [2] c7 1d [2] d9 00 [2] db 01 [2] c0 07 [2] dc 00 [2] c0 2f }

  condition:
    any of them
}