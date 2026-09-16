rule TTP_XOR_QUAD_CurrentVersionRun_a947 {
  strings:
    $key_a947 = { fa 28 [2] de 26 [2] f5 0a [2] db 28 [2] cf 33 [2] c0 29 [2] de 34 [2] dc 35 [2] c7 33 [2] db 34 [2] c7 1b }

  condition:
    any of them
}