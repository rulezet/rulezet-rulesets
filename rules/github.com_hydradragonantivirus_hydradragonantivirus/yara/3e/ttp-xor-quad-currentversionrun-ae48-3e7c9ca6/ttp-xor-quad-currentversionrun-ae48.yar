rule TTP_XOR_QUAD_CurrentVersionRun_ae48 {
  strings:
    $key_ae48 = { fd 27 [2] d9 29 [2] f2 05 [2] dc 27 [2] c8 3c [2] c7 26 [2] d9 3b [2] db 3a [2] c0 3c [2] dc 3b [2] c0 14 }

  condition:
    any of them
}