rule TTP_XOR_QUAD_CurrentVersionRun_ae0c {
  strings:
    $key_ae0c = { fd 63 [2] d9 6d [2] f2 41 [2] dc 63 [2] c8 78 [2] c7 62 [2] d9 7f [2] db 7e [2] c0 78 [2] dc 7f [2] c0 50 }

  condition:
    any of them
}