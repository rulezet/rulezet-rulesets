rule TTP_XOR_QUAD_CurrentVersionRun_a92c {
  strings:
    $key_a92c = { fa 43 [2] de 4d [2] f5 61 [2] db 43 [2] cf 58 [2] c0 42 [2] de 5f [2] dc 5e [2] c7 58 [2] db 5f [2] c7 70 }

  condition:
    any of them
}