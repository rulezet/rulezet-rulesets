rule TTP_XOR_QUAD_CurrentVersionRun_335a {
  strings:
    $key_335a = { 60 35 [2] 44 3b [2] 6f 17 [2] 41 35 [2] 55 2e [2] 5a 34 [2] 44 29 [2] 46 28 [2] 5d 2e [2] 41 29 [2] 5d 06 }

  condition:
    any of them
}