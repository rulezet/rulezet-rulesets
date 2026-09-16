rule TTP_XOR_QUAD_CurrentVersionRun_ae78 {
  strings:
    $key_ae78 = { fd 17 [2] d9 19 [2] f2 35 [2] dc 17 [2] c8 0c [2] c7 16 [2] d9 0b [2] db 0a [2] c0 0c [2] dc 0b [2] c0 24 }

  condition:
    any of them
}