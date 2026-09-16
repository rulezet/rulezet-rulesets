rule TTP_XOR_QUAD_CurrentVersionRun_ae76 {
  strings:
    $key_ae76 = { fd 19 [2] d9 17 [2] f2 3b [2] dc 19 [2] c8 02 [2] c7 18 [2] d9 05 [2] db 04 [2] c0 02 [2] dc 05 [2] c0 2a }

  condition:
    any of them
}