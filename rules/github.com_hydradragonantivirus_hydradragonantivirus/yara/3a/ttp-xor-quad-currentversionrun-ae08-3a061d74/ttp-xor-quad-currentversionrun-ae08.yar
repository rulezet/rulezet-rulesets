rule TTP_XOR_QUAD_CurrentVersionRun_ae08 {
  strings:
    $key_ae08 = { fd 67 [2] d9 69 [2] f2 45 [2] dc 67 [2] c8 7c [2] c7 66 [2] d9 7b [2] db 7a [2] c0 7c [2] dc 7b [2] c0 54 }

  condition:
    any of them
}