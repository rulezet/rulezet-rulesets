rule TTP_XOR_QUAD_CurrentVersionRun_a918 {
  strings:
    $key_a918 = { fa 77 [2] de 79 [2] f5 55 [2] db 77 [2] cf 6c [2] c0 76 [2] de 6b [2] dc 6a [2] c7 6c [2] db 6b [2] c7 44 }

  condition:
    any of them
}