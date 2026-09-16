rule TTP_XOR_QUAD_CurrentVersionRun_ae79 {
  strings:
    $key_ae79 = { fd 16 [2] d9 18 [2] f2 34 [2] dc 16 [2] c8 0d [2] c7 17 [2] d9 0a [2] db 0b [2] c0 0d [2] dc 0a [2] c0 25 }

  condition:
    any of them
}