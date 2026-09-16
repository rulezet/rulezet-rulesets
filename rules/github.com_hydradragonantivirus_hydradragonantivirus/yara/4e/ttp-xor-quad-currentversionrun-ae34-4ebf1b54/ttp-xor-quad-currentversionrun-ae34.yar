rule TTP_XOR_QUAD_CurrentVersionRun_ae34 {
  strings:
    $key_ae34 = { fd 5b [2] d9 55 [2] f2 79 [2] dc 5b [2] c8 40 [2] c7 5a [2] d9 47 [2] db 46 [2] c0 40 [2] dc 47 [2] c0 68 }

  condition:
    any of them
}