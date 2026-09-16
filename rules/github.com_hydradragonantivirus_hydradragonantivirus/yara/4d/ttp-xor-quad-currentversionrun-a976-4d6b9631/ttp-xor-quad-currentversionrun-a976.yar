rule TTP_XOR_QUAD_CurrentVersionRun_a976 {
  strings:
    $key_a976 = { fa 19 [2] de 17 [2] f5 3b [2] db 19 [2] cf 02 [2] c0 18 [2] de 05 [2] dc 04 [2] c7 02 [2] db 05 [2] c7 2a }

  condition:
    any of them
}