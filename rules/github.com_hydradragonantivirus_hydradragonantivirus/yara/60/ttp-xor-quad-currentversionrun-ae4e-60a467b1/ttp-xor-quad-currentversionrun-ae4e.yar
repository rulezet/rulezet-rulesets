rule TTP_XOR_QUAD_CurrentVersionRun_ae4e {
  strings:
    $key_ae4e = { fd 21 [2] d9 2f [2] f2 03 [2] dc 21 [2] c8 3a [2] c7 20 [2] d9 3d [2] db 3c [2] c0 3a [2] dc 3d [2] c0 12 }

  condition:
    any of them
}