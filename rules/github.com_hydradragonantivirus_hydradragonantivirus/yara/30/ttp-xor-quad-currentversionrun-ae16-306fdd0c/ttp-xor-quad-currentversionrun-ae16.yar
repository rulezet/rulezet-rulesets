rule TTP_XOR_QUAD_CurrentVersionRun_ae16 {
  strings:
    $key_ae16 = { fd 79 [2] d9 77 [2] f2 5b [2] dc 79 [2] c8 62 [2] c7 78 [2] d9 65 [2] db 64 [2] c0 62 [2] dc 65 [2] c0 4a }

  condition:
    any of them
}