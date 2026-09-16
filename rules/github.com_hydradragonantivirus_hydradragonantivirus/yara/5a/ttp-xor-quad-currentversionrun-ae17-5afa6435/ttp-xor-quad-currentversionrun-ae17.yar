rule TTP_XOR_QUAD_CurrentVersionRun_ae17 {
  strings:
    $key_ae17 = { fd 78 [2] d9 76 [2] f2 5a [2] dc 78 [2] c8 63 [2] c7 79 [2] d9 64 [2] db 65 [2] c0 63 [2] dc 64 [2] c0 4b }

  condition:
    any of them
}