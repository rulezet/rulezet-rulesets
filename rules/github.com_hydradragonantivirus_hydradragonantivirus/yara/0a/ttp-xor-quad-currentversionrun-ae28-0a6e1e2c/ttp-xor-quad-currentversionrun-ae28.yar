rule TTP_XOR_QUAD_CurrentVersionRun_ae28 {
  strings:
    $key_ae28 = { fd 47 [2] d9 49 [2] f2 65 [2] dc 47 [2] c8 5c [2] c7 46 [2] d9 5b [2] db 5a [2] c0 5c [2] dc 5b [2] c0 74 }

  condition:
    any of them
}