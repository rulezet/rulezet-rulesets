rule TTP_XOR_QUAD_CurrentVersionRun_442b {
  strings:
    $key_442b = { 17 44 [2] 33 4a [2] 18 66 [2] 36 44 [2] 22 5f [2] 2d 45 [2] 33 58 [2] 31 59 [2] 2a 5f [2] 36 58 [2] 2a 77 }

  condition:
    any of them
}