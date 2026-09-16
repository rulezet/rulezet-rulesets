rule TTP_XOR_QUAD_CurrentVersionRun_a94c {
  strings:
    $key_a94c = { fa 23 [2] de 2d [2] f5 01 [2] db 23 [2] cf 38 [2] c0 22 [2] de 3f [2] dc 3e [2] c7 38 [2] db 3f [2] c7 10 }

  condition:
    any of them
}