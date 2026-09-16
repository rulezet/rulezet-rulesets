rule TTP_XOR_QUAD_CurrentVersionRun_ae27 {
  strings:
    $key_ae27 = { fd 48 [2] d9 46 [2] f2 6a [2] dc 48 [2] c8 53 [2] c7 49 [2] d9 54 [2] db 55 [2] c0 53 [2] dc 54 [2] c0 7b }

  condition:
    any of them
}