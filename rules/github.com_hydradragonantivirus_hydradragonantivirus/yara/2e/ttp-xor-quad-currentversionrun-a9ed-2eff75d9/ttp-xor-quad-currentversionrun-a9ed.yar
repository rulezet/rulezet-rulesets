rule TTP_XOR_QUAD_CurrentVersionRun_a9ed {
  strings:
    $key_a9ed = { fa 82 [2] de 8c [2] f5 a0 [2] db 82 [2] cf 99 [2] c0 83 [2] de 9e [2] dc 9f [2] c7 99 [2] db 9e [2] c7 b1 }

  condition:
    any of them
}