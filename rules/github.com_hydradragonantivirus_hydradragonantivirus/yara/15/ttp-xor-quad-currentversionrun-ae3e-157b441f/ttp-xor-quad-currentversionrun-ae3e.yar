rule TTP_XOR_QUAD_CurrentVersionRun_ae3e {
  strings:
    $key_ae3e = { fd 51 [2] d9 5f [2] f2 73 [2] dc 51 [2] c8 4a [2] c7 50 [2] d9 4d [2] db 4c [2] c0 4a [2] dc 4d [2] c0 62 }

  condition:
    any of them
}