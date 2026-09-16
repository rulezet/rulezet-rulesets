rule TTP_XOR_QUAD_CurrentVersionRun_513a {
  strings:
    $key_513a = { 02 55 [2] 26 5b [2] 0d 77 [2] 23 55 [2] 37 4e [2] 38 54 [2] 26 49 [2] 24 48 [2] 3f 4e [2] 23 49 [2] 3f 66 }

  condition:
    any of them
}