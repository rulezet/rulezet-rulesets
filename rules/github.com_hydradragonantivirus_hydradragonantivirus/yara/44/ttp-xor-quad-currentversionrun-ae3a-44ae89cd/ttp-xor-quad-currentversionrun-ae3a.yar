rule TTP_XOR_QUAD_CurrentVersionRun_ae3a {
  strings:
    $key_ae3a = { fd 55 [2] d9 5b [2] f2 77 [2] dc 55 [2] c8 4e [2] c7 54 [2] d9 49 [2] db 48 [2] c0 4e [2] dc 49 [2] c0 66 }

  condition:
    any of them
}