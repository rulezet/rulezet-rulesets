rule TTP_XOR_QUAD_CurrentVersionRun_ae18 {
  strings:
    $key_ae18 = { fd 77 [2] d9 79 [2] f2 55 [2] dc 77 [2] c8 6c [2] c7 76 [2] d9 6b [2] db 6a [2] c0 6c [2] dc 6b [2] c0 44 }

  condition:
    any of them
}