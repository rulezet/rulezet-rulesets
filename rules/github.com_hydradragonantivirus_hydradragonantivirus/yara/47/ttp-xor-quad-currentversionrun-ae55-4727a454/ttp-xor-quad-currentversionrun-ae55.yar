rule TTP_XOR_QUAD_CurrentVersionRun_ae55 {
  strings:
    $key_ae55 = { fd 3a [2] d9 34 [2] f2 18 [2] dc 3a [2] c8 21 [2] c7 3b [2] d9 26 [2] db 27 [2] c0 21 [2] dc 26 [2] c0 09 }

  condition:
    any of them
}