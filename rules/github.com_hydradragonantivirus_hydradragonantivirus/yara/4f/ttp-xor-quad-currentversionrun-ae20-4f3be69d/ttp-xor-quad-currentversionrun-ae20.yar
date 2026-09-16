rule TTP_XOR_QUAD_CurrentVersionRun_ae20 {
  strings:
    $key_ae20 = { fd 4f [2] d9 41 [2] f2 6d [2] dc 4f [2] c8 54 [2] c7 4e [2] d9 53 [2] db 52 [2] c0 54 [2] dc 53 [2] c0 7c }

  condition:
    any of them
}