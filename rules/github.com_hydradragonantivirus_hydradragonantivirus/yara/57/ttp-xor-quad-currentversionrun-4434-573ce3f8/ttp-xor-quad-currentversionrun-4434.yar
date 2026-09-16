rule TTP_XOR_QUAD_CurrentVersionRun_4434 {
  strings:
    $key_4434 = { 17 5b [2] 33 55 [2] 18 79 [2] 36 5b [2] 22 40 [2] 2d 5a [2] 33 47 [2] 31 46 [2] 2a 40 [2] 36 47 [2] 2a 68 }

  condition:
    any of them
}