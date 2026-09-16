rule TTP_XOR_QUAD_CurrentVersionRun_a93a {
  strings:
    $key_a93a = { fa 55 [2] de 5b [2] f5 77 [2] db 55 [2] cf 4e [2] c0 54 [2] de 49 [2] dc 48 [2] c7 4e [2] db 49 [2] c7 66 }

  condition:
    any of them
}