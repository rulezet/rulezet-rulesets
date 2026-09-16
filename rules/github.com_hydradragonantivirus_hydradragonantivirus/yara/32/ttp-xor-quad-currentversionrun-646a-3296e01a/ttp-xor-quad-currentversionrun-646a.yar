rule TTP_XOR_QUAD_CurrentVersionRun_646a {
  strings:
    $key_646a = { 37 05 [2] 13 0b [2] 38 27 [2] 16 05 [2] 02 1e [2] 0d 04 [2] 13 19 [2] 11 18 [2] 0a 1e [2] 16 19 [2] 0a 36 }

  condition:
    any of them
}