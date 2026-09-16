rule TTP_XOR_QUAD_CurrentVersionRun_583a {
  strings:
    $key_583a = { 0b 55 [2] 2f 5b [2] 04 77 [2] 2a 55 [2] 3e 4e [2] 31 54 [2] 2f 49 [2] 2d 48 [2] 36 4e [2] 2a 49 [2] 36 66 }

  condition:
    any of them
}