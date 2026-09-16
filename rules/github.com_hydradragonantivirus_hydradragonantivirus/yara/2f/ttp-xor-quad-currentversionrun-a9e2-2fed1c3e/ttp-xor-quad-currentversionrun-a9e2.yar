rule TTP_XOR_QUAD_CurrentVersionRun_a9e2 {
  strings:
    $key_a9e2 = { fa 8d [2] de 83 [2] f5 af [2] db 8d [2] cf 96 [2] c0 8c [2] de 91 [2] dc 90 [2] c7 96 [2] db 91 [2] c7 be }

  condition:
    any of them
}