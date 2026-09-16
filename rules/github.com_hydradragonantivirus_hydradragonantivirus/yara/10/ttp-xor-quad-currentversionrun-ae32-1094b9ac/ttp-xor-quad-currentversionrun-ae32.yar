rule TTP_XOR_QUAD_CurrentVersionRun_ae32 {
  strings:
    $key_ae32 = { fd 5d [2] d9 53 [2] f2 7f [2] dc 5d [2] c8 46 [2] c7 5c [2] d9 41 [2] db 40 [2] c0 46 [2] dc 41 [2] c0 6e }

  condition:
    any of them
}