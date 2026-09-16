rule TTP_XOR_QUAD_CurrentVersionRun_a963 {
  strings:
    $key_a963 = { fa 0c [2] de 02 [2] f5 2e [2] db 0c [2] cf 17 [2] c0 0d [2] de 10 [2] dc 11 [2] c7 17 [2] db 10 [2] c7 3f }

  condition:
    any of them
}