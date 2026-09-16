rule TTP_XOR_QUAD_CurrentVersionRun_a901 {
  strings:
    $key_a901 = { fa 6e [2] de 60 [2] f5 4c [2] db 6e [2] cf 75 [2] c0 6f [2] de 72 [2] dc 73 [2] c7 75 [2] db 72 [2] c7 5d }

  condition:
    any of them
}