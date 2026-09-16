rule TTP_XOR_QUAD_CurrentVersionRun_ae1f {
  strings:
    $key_ae1f = { fd 70 [2] d9 7e [2] f2 52 [2] dc 70 [2] c8 6b [2] c7 71 [2] d9 6c [2] db 6d [2] c0 6b [2] dc 6c [2] c0 43 }

  condition:
    any of them
}