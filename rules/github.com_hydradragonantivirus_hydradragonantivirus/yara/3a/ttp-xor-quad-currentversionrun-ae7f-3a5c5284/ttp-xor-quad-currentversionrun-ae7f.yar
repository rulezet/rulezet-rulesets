rule TTP_XOR_QUAD_CurrentVersionRun_ae7f {
  strings:
    $key_ae7f = { fd 10 [2] d9 1e [2] f2 32 [2] dc 10 [2] c8 0b [2] c7 11 [2] d9 0c [2] db 0d [2] c0 0b [2] dc 0c [2] c0 23 }

  condition:
    any of them
}