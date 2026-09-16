rule TTP_XOR_QUAD_CurrentVersionRun_a928 {
  strings:
    $key_a928 = { fa 47 [2] de 49 [2] f5 65 [2] db 47 [2] cf 5c [2] c0 46 [2] de 5b [2] dc 5a [2] c7 5c [2] db 5b [2] c7 74 }

  condition:
    any of them
}