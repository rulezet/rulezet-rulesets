rule TTP_XOR_QUAD_CurrentVersionRun_ae45 {
  strings:
    $key_ae45 = { fd 2a [2] d9 24 [2] f2 08 [2] dc 2a [2] c8 31 [2] c7 2b [2] d9 36 [2] db 37 [2] c0 31 [2] dc 36 [2] c0 19 }

  condition:
    any of them
}