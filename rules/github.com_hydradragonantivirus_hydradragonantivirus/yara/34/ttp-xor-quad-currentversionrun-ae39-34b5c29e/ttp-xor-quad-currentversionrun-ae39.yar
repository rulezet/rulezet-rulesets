rule TTP_XOR_QUAD_CurrentVersionRun_ae39 {
  strings:
    $key_ae39 = { fd 56 [2] d9 58 [2] f2 74 [2] dc 56 [2] c8 4d [2] c7 57 [2] d9 4a [2] db 4b [2] c0 4d [2] dc 4a [2] c0 65 }

  condition:
    any of them
}