rule TTP_XOR_QUAD_CurrentVersionRun_ae68 {
  strings:
    $key_ae68 = { fd 07 [2] d9 09 [2] f2 25 [2] dc 07 [2] c8 1c [2] c7 06 [2] d9 1b [2] db 1a [2] c0 1c [2] dc 1b [2] c0 34 }

  condition:
    any of them
}