rule TTP_XOR_QUAD_CurrentVersionRun_5f3a {
  strings:
    $key_5f3a = { 0c 55 [2] 28 5b [2] 03 77 [2] 2d 55 [2] 39 4e [2] 36 54 [2] 28 49 [2] 2a 48 [2] 31 4e [2] 2d 49 [2] 31 66 }

  condition:
    any of them
}