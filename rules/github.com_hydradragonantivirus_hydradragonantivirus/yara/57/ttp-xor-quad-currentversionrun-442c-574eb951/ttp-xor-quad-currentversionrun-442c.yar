rule TTP_XOR_QUAD_CurrentVersionRun_442c {
  strings:
    $key_442c = { 17 43 [2] 33 4d [2] 18 61 [2] 36 43 [2] 22 58 [2] 2d 42 [2] 33 5f [2] 31 5e [2] 2a 58 [2] 36 5f [2] 2a 70 }

  condition:
    any of them
}