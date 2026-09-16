rule TTP_XOR_QUAD_CurrentVersionRun_543a {
  strings:
    $key_543a = { 07 55 [2] 23 5b [2] 08 77 [2] 26 55 [2] 32 4e [2] 3d 54 [2] 23 49 [2] 21 48 [2] 3a 4e [2] 26 49 [2] 3a 66 }

  condition:
    any of them
}