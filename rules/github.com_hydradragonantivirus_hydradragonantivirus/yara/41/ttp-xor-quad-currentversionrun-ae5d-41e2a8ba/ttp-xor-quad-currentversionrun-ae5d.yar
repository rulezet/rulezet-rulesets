rule TTP_XOR_QUAD_CurrentVersionRun_ae5d {
  strings:
    $key_ae5d = { fd 32 [2] d9 3c [2] f2 10 [2] dc 32 [2] c8 29 [2] c7 33 [2] d9 2e [2] db 2f [2] c0 29 [2] dc 2e [2] c0 01 }

  condition:
    any of them
}