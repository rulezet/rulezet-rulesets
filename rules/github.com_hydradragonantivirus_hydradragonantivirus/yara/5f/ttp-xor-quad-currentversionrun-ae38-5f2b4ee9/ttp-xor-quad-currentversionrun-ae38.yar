rule TTP_XOR_QUAD_CurrentVersionRun_ae38 {
  strings:
    $key_ae38 = { fd 57 [2] d9 59 [2] f2 75 [2] dc 57 [2] c8 4c [2] c7 56 [2] d9 4b [2] db 4a [2] c0 4c [2] dc 4b [2] c0 64 }

  condition:
    any of them
}