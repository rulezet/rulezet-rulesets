rule TTP_XOR_QUAD_CurrentVersionRun_ae47 {
  strings:
    $key_ae47 = { fd 28 [2] d9 26 [2] f2 0a [2] dc 28 [2] c8 33 [2] c7 29 [2] d9 34 [2] db 35 [2] c0 33 [2] dc 34 [2] c0 1b }

  condition:
    any of them
}