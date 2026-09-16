rule TTP_XOR_QUAD_CurrentVersionRun_ae30 {
  strings:
    $key_ae30 = { fd 5f [2] d9 51 [2] f2 7d [2] dc 5f [2] c8 44 [2] c7 5e [2] d9 43 [2] db 42 [2] c0 44 [2] dc 43 [2] c0 6c }

  condition:
    any of them
}