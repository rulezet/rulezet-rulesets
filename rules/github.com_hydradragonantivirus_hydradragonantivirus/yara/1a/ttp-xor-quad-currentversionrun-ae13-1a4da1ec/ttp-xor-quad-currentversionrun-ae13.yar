rule TTP_XOR_QUAD_CurrentVersionRun_ae13 {
  strings:
    $key_ae13 = { fd 7c [2] d9 72 [2] f2 5e [2] dc 7c [2] c8 67 [2] c7 7d [2] d9 60 [2] db 61 [2] c0 67 [2] dc 60 [2] c0 4f }

  condition:
    any of them
}