rule TTP_XOR_QUAD_CurrentVersionRun_ae4a {
  strings:
    $key_ae4a = { fd 25 [2] d9 2b [2] f2 07 [2] dc 25 [2] c8 3e [2] c7 24 [2] d9 39 [2] db 38 [2] c0 3e [2] dc 39 [2] c0 16 }

  condition:
    any of them
}