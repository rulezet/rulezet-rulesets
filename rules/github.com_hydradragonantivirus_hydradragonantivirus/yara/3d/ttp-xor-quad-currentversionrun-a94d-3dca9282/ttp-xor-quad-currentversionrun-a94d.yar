rule TTP_XOR_QUAD_CurrentVersionRun_a94d {
  strings:
    $key_a94d = { fa 22 [2] de 2c [2] f5 00 [2] db 22 [2] cf 39 [2] c0 23 [2] de 3e [2] dc 3f [2] c7 39 [2] db 3e [2] c7 11 }

  condition:
    any of them
}