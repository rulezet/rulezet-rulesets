rule TTP_XOR_QUAD_CurrentVersionRun_ae14 {
  strings:
    $key_ae14 = { fd 7b [2] d9 75 [2] f2 59 [2] dc 7b [2] c8 60 [2] c7 7a [2] d9 67 [2] db 66 [2] c0 60 [2] dc 67 [2] c0 48 }

  condition:
    any of them
}