rule TTP_XOR_QUAD_CurrentVersionRun_ae1c {
  strings:
    $key_ae1c = { fd 73 [2] d9 7d [2] f2 51 [2] dc 73 [2] c8 68 [2] c7 72 [2] d9 6f [2] db 6e [2] c0 68 [2] dc 6f [2] c0 40 }

  condition:
    any of them
}