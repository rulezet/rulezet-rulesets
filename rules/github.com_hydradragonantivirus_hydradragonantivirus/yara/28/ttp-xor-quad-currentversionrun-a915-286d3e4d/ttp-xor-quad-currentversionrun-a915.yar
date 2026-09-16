rule TTP_XOR_QUAD_CurrentVersionRun_a915 {
  strings:
    $key_a915 = { fa 7a [2] de 74 [2] f5 58 [2] db 7a [2] cf 61 [2] c0 7b [2] de 66 [2] dc 67 [2] c7 61 [2] db 66 [2] c7 49 }

  condition:
    any of them
}