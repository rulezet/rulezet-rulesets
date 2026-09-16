rule TTP_XOR_QUAD_CurrentVersionRun_513d {
  strings:
    $key_513d = { 02 52 [2] 26 5c [2] 0d 70 [2] 23 52 [2] 37 49 [2] 38 53 [2] 26 4e [2] 24 4f [2] 3f 49 [2] 23 4e [2] 3f 61 }

  condition:
    any of them
}