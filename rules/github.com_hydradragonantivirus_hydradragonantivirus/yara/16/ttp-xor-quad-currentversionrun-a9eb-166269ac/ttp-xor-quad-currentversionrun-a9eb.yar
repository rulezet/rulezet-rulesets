rule TTP_XOR_QUAD_CurrentVersionRun_a9eb {
  strings:
    $key_a9eb = { fa 84 [2] de 8a [2] f5 a6 [2] db 84 [2] cf 9f [2] c0 85 [2] de 98 [2] dc 99 [2] c7 9f [2] db 98 [2] c7 b7 }

  condition:
    any of them
}