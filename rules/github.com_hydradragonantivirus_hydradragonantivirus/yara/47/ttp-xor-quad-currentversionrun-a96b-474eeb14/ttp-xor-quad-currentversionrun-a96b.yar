rule TTP_XOR_QUAD_CurrentVersionRun_a96b {
  strings:
    $key_a96b = { fa 04 [2] de 0a [2] f5 26 [2] db 04 [2] cf 1f [2] c0 05 [2] de 18 [2] dc 19 [2] c7 1f [2] db 18 [2] c7 37 }

  condition:
    any of them
}