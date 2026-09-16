rule TTP_XOR_QUAD_CurrentVersionRun_ae7b {
  strings:
    $key_ae7b = { fd 14 [2] d9 1a [2] f2 36 [2] dc 14 [2] c8 0f [2] c7 15 [2] d9 08 [2] db 09 [2] c0 0f [2] dc 08 [2] c0 27 }

  condition:
    any of them
}