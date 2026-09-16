rule TTP_XOR_QUAD_CurrentVersionRun_646d {
  strings:
    $key_646d = { 37 02 [2] 13 0c [2] 38 20 [2] 16 02 [2] 02 19 [2] 0d 03 [2] 13 1e [2] 11 1f [2] 0a 19 [2] 16 1e [2] 0a 31 }

  condition:
    any of them
}