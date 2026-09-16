rule TTP_XOR_QUAD_CurrentVersionRun_aefc {
  strings:
    $key_aefc = { fd 93 [2] d9 9d [2] f2 b1 [2] dc 93 [2] c8 88 [2] c7 92 [2] d9 8f [2] db 8e [2] c0 88 [2] dc 8f [2] c0 a0 }

  condition:
    any of them
}