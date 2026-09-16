rule TTP_XOR_QUAD_CurrentVersionRun_ae3b {
  strings:
    $key_ae3b = { fd 54 [2] d9 5a [2] f2 76 [2] dc 54 [2] c8 4f [2] c7 55 [2] d9 48 [2] db 49 [2] c0 4f [2] dc 48 [2] c0 67 }

  condition:
    any of them
}