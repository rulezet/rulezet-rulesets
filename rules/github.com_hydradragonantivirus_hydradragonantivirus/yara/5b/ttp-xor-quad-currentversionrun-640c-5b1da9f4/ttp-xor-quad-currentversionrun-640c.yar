rule TTP_XOR_QUAD_CurrentVersionRun_640c {
  strings:
    $key_640c = { 37 63 [2] 13 6d [2] 38 41 [2] 16 63 [2] 02 78 [2] 0d 62 [2] 13 7f [2] 11 7e [2] 0a 78 [2] 16 7f [2] 0a 50 }

  condition:
    any of them
}