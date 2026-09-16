rule TTP_XOR_QUAD_CurrentVersionRun_a945 {
  strings:
    $key_a945 = { fa 2a [2] de 24 [2] f5 08 [2] db 2a [2] cf 31 [2] c0 2b [2] de 36 [2] dc 37 [2] c7 31 [2] db 36 [2] c7 19 }

  condition:
    any of them
}