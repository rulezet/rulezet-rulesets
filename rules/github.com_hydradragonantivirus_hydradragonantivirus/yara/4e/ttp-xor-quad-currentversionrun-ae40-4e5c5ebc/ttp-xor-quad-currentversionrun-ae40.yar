rule TTP_XOR_QUAD_CurrentVersionRun_ae40 {
  strings:
    $key_ae40 = { fd 2f [2] d9 21 [2] f2 0d [2] dc 2f [2] c8 34 [2] c7 2e [2] d9 33 [2] db 32 [2] c0 34 [2] dc 33 [2] c0 1c }

  condition:
    any of them
}