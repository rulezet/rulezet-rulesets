rule TTP_XOR_QUAD_CurrentVersionRun_a94b {
  strings:
    $key_a94b = { fa 24 [2] de 2a [2] f5 06 [2] db 24 [2] cf 3f [2] c0 25 [2] de 38 [2] dc 39 [2] c7 3f [2] db 38 [2] c7 17 }

  condition:
    any of them
}