rule TTP_XOR_QUAD_CurrentVersionRun_ae54 {
  strings:
    $key_ae54 = { fd 3b [2] d9 35 [2] f2 19 [2] dc 3b [2] c8 20 [2] c7 3a [2] d9 27 [2] db 26 [2] c0 20 [2] dc 27 [2] c0 08 }

  condition:
    any of them
}