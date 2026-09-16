rule TTP_XOR_QUAD_CurrentVersionRun_a910 {
  strings:
    $key_a910 = { fa 7f [2] de 71 [2] f5 5d [2] db 7f [2] cf 64 [2] c0 7e [2] de 63 [2] dc 62 [2] c7 64 [2] db 63 [2] c7 4c }

  condition:
    any of them
}