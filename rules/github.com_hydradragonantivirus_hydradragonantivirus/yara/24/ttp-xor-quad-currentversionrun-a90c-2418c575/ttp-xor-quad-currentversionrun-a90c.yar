rule TTP_XOR_QUAD_CurrentVersionRun_a90c {
  strings:
    $key_a90c = { fa 63 [2] de 6d [2] f5 41 [2] db 63 [2] cf 78 [2] c0 62 [2] de 7f [2] dc 7e [2] c7 78 [2] db 7f [2] c7 50 }

  condition:
    any of them
}