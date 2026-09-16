rule TTP_XOR_QUAD_CurrentVersionRun_a921 {
  strings:
    $key_a921 = { fa 4e [2] de 40 [2] f5 6c [2] db 4e [2] cf 55 [2] c0 4f [2] de 52 [2] dc 53 [2] c7 55 [2] db 52 [2] c7 7d }

  condition:
    any of them
}