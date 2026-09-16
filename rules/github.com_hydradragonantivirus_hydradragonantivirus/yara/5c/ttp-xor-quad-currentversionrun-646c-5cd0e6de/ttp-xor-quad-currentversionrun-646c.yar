rule TTP_XOR_QUAD_CurrentVersionRun_646c {
  strings:
    $key_646c = { 37 03 [2] 13 0d [2] 38 21 [2] 16 03 [2] 02 18 [2] 0d 02 [2] 13 1f [2] 11 1e [2] 0a 18 [2] 16 1f [2] 0a 30 }

  condition:
    any of them
}