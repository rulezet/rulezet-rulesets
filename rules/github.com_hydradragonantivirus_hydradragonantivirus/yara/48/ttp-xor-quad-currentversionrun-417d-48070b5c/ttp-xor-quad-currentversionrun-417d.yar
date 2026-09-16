rule TTP_XOR_QUAD_CurrentVersionRun_417d {
  strings:
    $key_417d = { 12 12 [2] 36 1c [2] 1d 30 [2] 33 12 [2] 27 09 [2] 28 13 [2] 36 0e [2] 34 0f [2] 2f 09 [2] 33 0e [2] 2f 21 }

  condition:
    any of them
}