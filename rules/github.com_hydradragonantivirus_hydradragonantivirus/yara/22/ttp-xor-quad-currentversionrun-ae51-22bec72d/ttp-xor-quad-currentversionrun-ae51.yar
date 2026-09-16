rule TTP_XOR_QUAD_CurrentVersionRun_ae51 {
  strings:
    $key_ae51 = { fd 3e [2] d9 30 [2] f2 1c [2] dc 3e [2] c8 25 [2] c7 3f [2] d9 22 [2] db 23 [2] c0 25 [2] dc 22 [2] c0 0d }

  condition:
    any of them
}