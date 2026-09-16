rule TTP_XOR_QUAD_CurrentVersionRun_a913 {
  strings:
    $key_a913 = { fa 7c [2] de 72 [2] f5 5e [2] db 7c [2] cf 67 [2] c0 7d [2] de 60 [2] dc 61 [2] c7 67 [2] db 60 [2] c7 4f }

  condition:
    any of them
}