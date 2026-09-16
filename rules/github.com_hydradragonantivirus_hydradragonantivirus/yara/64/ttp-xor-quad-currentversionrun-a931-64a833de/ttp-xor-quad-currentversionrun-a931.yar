rule TTP_XOR_QUAD_CurrentVersionRun_a931 {
  strings:
    $key_a931 = { fa 5e [2] de 50 [2] f5 7c [2] db 5e [2] cf 45 [2] c0 5f [2] de 42 [2] dc 43 [2] c7 45 [2] db 42 [2] c7 6d }

  condition:
    any of them
}