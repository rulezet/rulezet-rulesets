rule TTP_XOR_QUAD_CurrentVersionRun_a93d {
  strings:
    $key_a93d = { fa 52 [2] de 5c [2] f5 70 [2] db 52 [2] cf 49 [2] c0 53 [2] de 4e [2] dc 4f [2] c7 49 [2] db 4e [2] c7 61 }

  condition:
    any of them
}