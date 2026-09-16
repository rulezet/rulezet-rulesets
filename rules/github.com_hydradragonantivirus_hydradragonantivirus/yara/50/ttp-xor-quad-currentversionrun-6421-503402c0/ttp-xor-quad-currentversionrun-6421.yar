rule TTP_XOR_QUAD_CurrentVersionRun_6421 {
  strings:
    $key_6421 = { 37 4e [2] 13 40 [2] 38 6c [2] 16 4e [2] 02 55 [2] 0d 4f [2] 13 52 [2] 11 53 [2] 0a 55 [2] 16 52 [2] 0a 7d }

  condition:
    any of them
}