rule TTP_XOR_QUAD_CurrentVersionRun_a9ff {
  strings:
    $key_a9ff = { fa 90 [2] de 9e [2] f5 b2 [2] db 90 [2] cf 8b [2] c0 91 [2] de 8c [2] dc 8d [2] c7 8b [2] db 8c [2] c7 a3 }

  condition:
    any of them
}