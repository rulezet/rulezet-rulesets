rule TTP_XOR_QUAD_CurrentVersionRun_ae4b {
  strings:
    $key_ae4b = { fd 24 [2] d9 2a [2] f2 06 [2] dc 24 [2] c8 3f [2] c7 25 [2] d9 38 [2] db 39 [2] c0 3f [2] dc 38 [2] c0 17 }

  condition:
    any of them
}