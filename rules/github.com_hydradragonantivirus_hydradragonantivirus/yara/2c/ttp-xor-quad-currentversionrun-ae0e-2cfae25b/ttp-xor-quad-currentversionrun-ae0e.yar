rule TTP_XOR_QUAD_CurrentVersionRun_ae0e {
  strings:
    $key_ae0e = { fd 61 [2] d9 6f [2] f2 43 [2] dc 61 [2] c8 7a [2] c7 60 [2] d9 7d [2] db 7c [2] c0 7a [2] dc 7d [2] c0 52 }

  condition:
    any of them
}