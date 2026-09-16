rule TTP_XOR_QUAD_CurrentVersionRun_643d {
  strings:
    $key_643d = { 37 52 [2] 13 5c [2] 38 70 [2] 16 52 [2] 02 49 [2] 0d 53 [2] 13 4e [2] 11 4f [2] 0a 49 [2] 16 4e [2] 0a 61 }

  condition:
    any of them
}