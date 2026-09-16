rule TTP_XOR_QUAD_CurrentVersionRun_a911 {
  strings:
    $key_a911 = { fa 7e [2] de 70 [2] f5 5c [2] db 7e [2] cf 65 [2] c0 7f [2] de 62 [2] dc 63 [2] c7 65 [2] db 62 [2] c7 4d }

  condition:
    any of them
}