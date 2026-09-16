rule TTP_XOR_QUAD_CurrentVersionRun_ae7c {
  strings:
    $key_ae7c = { fd 13 [2] d9 1d [2] f2 31 [2] dc 13 [2] c8 08 [2] c7 12 [2] d9 0f [2] db 0e [2] c0 08 [2] dc 0f [2] c0 20 }

  condition:
    any of them
}