rule TTP_XOR_QUAD_CurrentVersionRun_ae77 {
  strings:
    $key_ae77 = { fd 18 [2] d9 16 [2] f2 3a [2] dc 18 [2] c8 03 [2] c7 19 [2] d9 04 [2] db 05 [2] c0 03 [2] dc 04 [2] c0 2b }

  condition:
    any of them
}