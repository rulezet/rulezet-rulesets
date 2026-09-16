rule TTP_XOR_QUAD_CurrentVersionRun_ae21 {
  strings:
    $key_ae21 = { fd 4e [2] d9 40 [2] f2 6c [2] dc 4e [2] c8 55 [2] c7 4f [2] d9 52 [2] db 53 [2] c0 55 [2] dc 52 [2] c0 7d }

  condition:
    any of them
}