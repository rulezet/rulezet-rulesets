rule TTP_XOR_QUAD_CurrentVersionRun_a902 {
  strings:
    $key_a902 = { fa 6d [2] de 63 [2] f5 4f [2] db 6d [2] cf 76 [2] c0 6c [2] de 71 [2] dc 70 [2] c7 76 [2] db 71 [2] c7 5e }

  condition:
    any of them
}