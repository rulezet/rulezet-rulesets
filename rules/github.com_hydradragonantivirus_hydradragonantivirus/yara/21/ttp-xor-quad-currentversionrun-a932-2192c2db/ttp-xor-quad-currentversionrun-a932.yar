rule TTP_XOR_QUAD_CurrentVersionRun_a932 {
  strings:
    $key_a932 = { fa 5d [2] de 53 [2] f5 7f [2] db 5d [2] cf 46 [2] c0 5c [2] de 41 [2] dc 40 [2] c7 46 [2] db 41 [2] c7 6e }

  condition:
    any of them
}