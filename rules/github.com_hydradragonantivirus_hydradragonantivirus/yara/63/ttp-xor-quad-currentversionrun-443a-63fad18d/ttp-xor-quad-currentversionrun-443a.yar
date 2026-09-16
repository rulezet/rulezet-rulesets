rule TTP_XOR_QUAD_CurrentVersionRun_443a {
  strings:
    $key_443a = { 17 55 [2] 33 5b [2] 18 77 [2] 36 55 [2] 22 4e [2] 2d 54 [2] 33 49 [2] 31 48 [2] 2a 4e [2] 36 49 [2] 2a 66 }

  condition:
    any of them
}