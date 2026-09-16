rule TTP_XOR_QUAD_CurrentVersionRun_440c {
  strings:
    $key_440c = { 17 63 [2] 33 6d [2] 18 41 [2] 36 63 [2] 22 78 [2] 2d 62 [2] 33 7f [2] 31 7e [2] 2a 78 [2] 36 7f [2] 2a 50 }

  condition:
    any of them
}