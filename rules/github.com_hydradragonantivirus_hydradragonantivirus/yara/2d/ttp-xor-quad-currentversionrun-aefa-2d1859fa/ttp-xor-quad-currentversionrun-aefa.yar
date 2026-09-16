rule TTP_XOR_QUAD_CurrentVersionRun_aefa {
  strings:
    $key_aefa = { fd 95 [2] d9 9b [2] f2 b7 [2] dc 95 [2] c8 8e [2] c7 94 [2] d9 89 [2] db 88 [2] c0 8e [2] dc 89 [2] c0 a6 }

  condition:
    any of them
}