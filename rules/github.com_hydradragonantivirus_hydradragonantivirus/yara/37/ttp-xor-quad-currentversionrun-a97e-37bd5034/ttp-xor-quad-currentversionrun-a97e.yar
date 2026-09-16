rule TTP_XOR_QUAD_CurrentVersionRun_a97e {
  strings:
    $key_a97e = { fa 11 [2] de 1f [2] f5 33 [2] db 11 [2] cf 0a [2] c0 10 [2] de 0d [2] dc 0c [2] c7 0a [2] db 0d [2] c7 22 }

  condition:
    any of them
}