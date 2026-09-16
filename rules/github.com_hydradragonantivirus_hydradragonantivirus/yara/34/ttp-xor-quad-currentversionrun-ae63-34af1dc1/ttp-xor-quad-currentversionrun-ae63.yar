rule TTP_XOR_QUAD_CurrentVersionRun_ae63 {
  strings:
    $key_ae63 = { fd 0c [2] d9 02 [2] f2 2e [2] dc 0c [2] c8 17 [2] c7 0d [2] d9 10 [2] db 11 [2] c0 17 [2] dc 10 [2] c0 3f }

  condition:
    any of them
}