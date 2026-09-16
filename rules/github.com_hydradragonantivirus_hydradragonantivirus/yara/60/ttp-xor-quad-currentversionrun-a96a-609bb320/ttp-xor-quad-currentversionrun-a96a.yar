rule TTP_XOR_QUAD_CurrentVersionRun_a96a {
  strings:
    $key_a96a = { fa 05 [2] de 0b [2] f5 27 [2] db 05 [2] cf 1e [2] c0 04 [2] de 19 [2] dc 18 [2] c7 1e [2] db 19 [2] c7 36 }

  condition:
    any of them
}