rule TTP_XOR_QUAD_CurrentVersionRun_a9fb {
  strings:
    $key_a9fb = { fa 94 [2] de 9a [2] f5 b6 [2] db 94 [2] cf 8f [2] c0 95 [2] de 88 [2] dc 89 [2] c7 8f [2] db 88 [2] c7 a7 }

  condition:
    any of them
}