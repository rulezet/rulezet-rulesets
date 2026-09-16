rule TTP_XOR_QUAD_CurrentVersionRun_a914 {
  strings:
    $key_a914 = { fa 7b [2] de 75 [2] f5 59 [2] db 7b [2] cf 60 [2] c0 7a [2] de 67 [2] dc 66 [2] c7 60 [2] db 67 [2] c7 48 }

  condition:
    any of them
}