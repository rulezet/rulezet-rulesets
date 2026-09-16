rule TTP_XOR_QUAD_CurrentVersionRun_ae3f {
  strings:
    $key_ae3f = { fd 50 [2] d9 5e [2] f2 72 [2] dc 50 [2] c8 4b [2] c7 51 [2] d9 4c [2] db 4d [2] c0 4b [2] dc 4c [2] c0 63 }

  condition:
    any of them
}