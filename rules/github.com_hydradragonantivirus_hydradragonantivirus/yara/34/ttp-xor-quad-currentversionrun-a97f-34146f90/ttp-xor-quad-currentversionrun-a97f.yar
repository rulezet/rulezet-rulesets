rule TTP_XOR_QUAD_CurrentVersionRun_a97f {
  strings:
    $key_a97f = { fa 10 [2] de 1e [2] f5 32 [2] db 10 [2] cf 0b [2] c0 11 [2] de 0c [2] dc 0d [2] c7 0b [2] db 0c [2] c7 23 }

  condition:
    any of them
}