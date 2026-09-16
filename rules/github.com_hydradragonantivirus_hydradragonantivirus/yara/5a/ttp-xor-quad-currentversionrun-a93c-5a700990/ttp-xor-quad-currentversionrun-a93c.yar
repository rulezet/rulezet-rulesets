rule TTP_XOR_QUAD_CurrentVersionRun_a93c {
  strings:
    $key_a93c = { fa 53 [2] de 5d [2] f5 71 [2] db 53 [2] cf 48 [2] c0 52 [2] de 4f [2] dc 4e [2] c7 48 [2] db 4f [2] c7 60 }

  condition:
    any of them
}