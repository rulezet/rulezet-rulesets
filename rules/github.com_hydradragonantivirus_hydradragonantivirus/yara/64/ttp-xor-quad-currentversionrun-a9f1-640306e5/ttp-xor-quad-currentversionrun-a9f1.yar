rule TTP_XOR_QUAD_CurrentVersionRun_a9f1 {
  strings:
    $key_a9f1 = { fa 9e [2] de 90 [2] f5 bc [2] db 9e [2] cf 85 [2] c0 9f [2] de 82 [2] dc 83 [2] c7 85 [2] db 82 [2] c7 ad }

  condition:
    any of them
}