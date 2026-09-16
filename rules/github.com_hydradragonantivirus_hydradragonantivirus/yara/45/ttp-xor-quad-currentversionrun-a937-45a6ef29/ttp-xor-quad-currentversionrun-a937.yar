rule TTP_XOR_QUAD_CurrentVersionRun_a937 {
  strings:
    $key_a937 = { fa 58 [2] de 56 [2] f5 7a [2] db 58 [2] cf 43 [2] c0 59 [2] de 44 [2] dc 45 [2] c7 43 [2] db 44 [2] c7 6b }

  condition:
    any of them
}