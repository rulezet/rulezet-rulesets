rule TTP_XOR_QUAD_CurrentVersionRun_a905 {
  strings:
    $key_a905 = { fa 6a [2] de 64 [2] f5 48 [2] db 6a [2] cf 71 [2] c0 6b [2] de 76 [2] dc 77 [2] c7 71 [2] db 76 [2] c7 59 }

  condition:
    any of them
}