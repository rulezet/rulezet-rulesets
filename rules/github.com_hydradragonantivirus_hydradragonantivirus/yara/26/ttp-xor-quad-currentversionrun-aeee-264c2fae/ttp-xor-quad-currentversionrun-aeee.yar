rule TTP_XOR_QUAD_CurrentVersionRun_aeee {
  strings:
    $key_aeee = { fd 81 [2] d9 8f [2] f2 a3 [2] dc 81 [2] c8 9a [2] c7 80 [2] d9 9d [2] db 9c [2] c0 9a [2] dc 9d [2] c0 b2 }

  condition:
    any of them
}