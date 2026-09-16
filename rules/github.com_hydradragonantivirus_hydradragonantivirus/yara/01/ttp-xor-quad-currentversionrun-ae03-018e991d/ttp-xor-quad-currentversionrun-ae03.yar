rule TTP_XOR_QUAD_CurrentVersionRun_ae03 {
  strings:
    $key_ae03 = { fd 6c [2] d9 62 [2] f2 4e [2] dc 6c [2] c8 77 [2] c7 6d [2] d9 70 [2] db 71 [2] c0 77 [2] dc 70 [2] c0 5f }

  condition:
    any of them
}