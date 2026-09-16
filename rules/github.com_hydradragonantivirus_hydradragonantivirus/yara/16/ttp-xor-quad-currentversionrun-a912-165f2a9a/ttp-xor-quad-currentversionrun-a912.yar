rule TTP_XOR_QUAD_CurrentVersionRun_a912 {
  strings:
    $key_a912 = { fa 7d [2] de 73 [2] f5 5f [2] db 7d [2] cf 66 [2] c0 7c [2] de 61 [2] dc 60 [2] c7 66 [2] db 61 [2] c7 4e }

  condition:
    any of them
}