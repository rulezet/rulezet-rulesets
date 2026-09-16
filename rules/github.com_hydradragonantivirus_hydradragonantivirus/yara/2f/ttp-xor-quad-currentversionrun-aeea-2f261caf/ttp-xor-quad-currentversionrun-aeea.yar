rule TTP_XOR_QUAD_CurrentVersionRun_aeea {
  strings:
    $key_aeea = { fd 85 [2] d9 8b [2] f2 a7 [2] dc 85 [2] c8 9e [2] c7 84 [2] d9 99 [2] db 98 [2] c0 9e [2] dc 99 [2] c0 b6 }

  condition:
    any of them
}