rule TTP_XOR_QUAD_CurrentVersionRun_6420 {
  strings:
    $key_6420 = { 37 4f [2] 13 41 [2] 38 6d [2] 16 4f [2] 02 54 [2] 0d 4e [2] 13 53 [2] 11 52 [2] 0a 54 [2] 16 53 [2] 0a 7c }

  condition:
    any of them
}