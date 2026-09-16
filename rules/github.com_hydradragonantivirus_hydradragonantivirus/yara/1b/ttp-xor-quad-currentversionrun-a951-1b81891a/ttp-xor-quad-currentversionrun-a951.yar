rule TTP_XOR_QUAD_CurrentVersionRun_a951 {
  strings:
    $key_a951 = { fa 3e [2] de 30 [2] f5 1c [2] db 3e [2] cf 25 [2] c0 3f [2] de 22 [2] dc 23 [2] c7 25 [2] db 22 [2] c7 0d }

  condition:
    any of them
}