rule TTP_XOR_QUAD_CurrentVersionRun_a92b {
  strings:
    $key_a92b = { fa 44 [2] de 4a [2] f5 66 [2] db 44 [2] cf 5f [2] c0 45 [2] de 58 [2] dc 59 [2] c7 5f [2] db 58 [2] c7 77 }

  condition:
    any of them
}