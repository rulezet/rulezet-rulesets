rule TTP_XOR_QUAD_CurrentVersionRun_ae15 {
  strings:
    $key_ae15 = { fd 7a [2] d9 74 [2] f2 58 [2] dc 7a [2] c8 61 [2] c7 7b [2] d9 66 [2] db 67 [2] c0 61 [2] dc 66 [2] c0 49 }

  condition:
    any of them
}