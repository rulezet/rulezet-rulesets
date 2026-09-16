rule TTP_XOR_QUAD_CurrentVersionRun_543d {
  strings:
    $key_543d = { 07 52 [2] 23 5c [2] 08 70 [2] 26 52 [2] 32 49 [2] 3d 53 [2] 23 4e [2] 21 4f [2] 3a 49 [2] 26 4e [2] 3a 61 }

  condition:
    any of them
}