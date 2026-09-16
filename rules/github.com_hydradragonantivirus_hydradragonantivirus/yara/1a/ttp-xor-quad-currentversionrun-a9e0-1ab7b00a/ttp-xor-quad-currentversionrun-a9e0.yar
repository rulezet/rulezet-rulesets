rule TTP_XOR_QUAD_CurrentVersionRun_a9e0 {
  strings:
    $key_a9e0 = { fa 8f [2] de 81 [2] f5 ad [2] db 8f [2] cf 94 [2] c0 8e [2] de 93 [2] dc 92 [2] c7 94 [2] db 93 [2] c7 bc }

  condition:
    any of them
}