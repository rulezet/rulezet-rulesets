rule TTP_XOR_QUAD_CurrentVersionRun_ae75 {
  strings:
    $key_ae75 = { fd 1a [2] d9 14 [2] f2 38 [2] dc 1a [2] c8 01 [2] c7 1b [2] d9 06 [2] db 07 [2] c0 01 [2] dc 06 [2] c0 29 }

  condition:
    any of them
}