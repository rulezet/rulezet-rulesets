rule TTP_XOR_QUAD_CurrentVersionRun_432a {
  strings:
    $key_432a = { 10 45 [2] 34 4b [2] 1f 67 [2] 31 45 [2] 25 5e [2] 2a 44 [2] 34 59 [2] 36 58 [2] 2d 5e [2] 31 59 [2] 2d 76 }

  condition:
    any of them
}