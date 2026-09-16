rule TTP_XOR_QUAD_CurrentVersionRun_417b {
  strings:
    $key_417b = { 12 14 [2] 36 1a [2] 1d 36 [2] 33 14 [2] 27 0f [2] 28 15 [2] 36 08 [2] 34 09 [2] 2f 0f [2] 33 08 [2] 2f 27 }

  condition:
    any of them
}