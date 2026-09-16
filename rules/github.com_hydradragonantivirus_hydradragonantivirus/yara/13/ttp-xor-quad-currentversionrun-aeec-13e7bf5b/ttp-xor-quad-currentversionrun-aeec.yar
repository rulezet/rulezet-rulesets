rule TTP_XOR_QUAD_CurrentVersionRun_aeec {
  strings:
    $key_aeec = { fd 83 [2] d9 8d [2] f2 a1 [2] dc 83 [2] c8 98 [2] c7 82 [2] d9 9f [2] db 9e [2] c0 98 [2] dc 9f [2] c0 b0 }

  condition:
    any of them
}