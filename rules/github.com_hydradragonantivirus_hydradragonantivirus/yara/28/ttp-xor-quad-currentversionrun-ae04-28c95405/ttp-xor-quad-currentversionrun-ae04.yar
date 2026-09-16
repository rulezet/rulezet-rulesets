rule TTP_XOR_QUAD_CurrentVersionRun_ae04 {
  strings:
    $key_ae04 = { fd 6b [2] d9 65 [2] f2 49 [2] dc 6b [2] c8 70 [2] c7 6a [2] d9 77 [2] db 76 [2] c0 70 [2] dc 77 [2] c0 58 }

  condition:
    any of them
}