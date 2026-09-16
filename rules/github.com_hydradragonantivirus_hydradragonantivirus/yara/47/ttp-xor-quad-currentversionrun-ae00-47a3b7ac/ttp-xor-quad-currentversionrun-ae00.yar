rule TTP_XOR_QUAD_CurrentVersionRun_ae00 {
  strings:
    $key_ae00 = { fd 6f [2] d9 61 [2] f2 4d [2] dc 6f [2] c8 74 [2] c7 6e [2] d9 73 [2] db 72 [2] c0 74 [2] dc 73 [2] c0 5c }

  condition:
    any of them
}