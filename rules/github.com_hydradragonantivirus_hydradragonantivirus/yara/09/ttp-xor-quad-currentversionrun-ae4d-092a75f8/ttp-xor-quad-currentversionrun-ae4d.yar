rule TTP_XOR_QUAD_CurrentVersionRun_ae4d {
  strings:
    $key_ae4d = { fd 22 [2] d9 2c [2] f2 00 [2] dc 22 [2] c8 39 [2] c7 23 [2] d9 3e [2] db 3f [2] c0 39 [2] dc 3e [2] c0 11 }

  condition:
    any of them
}