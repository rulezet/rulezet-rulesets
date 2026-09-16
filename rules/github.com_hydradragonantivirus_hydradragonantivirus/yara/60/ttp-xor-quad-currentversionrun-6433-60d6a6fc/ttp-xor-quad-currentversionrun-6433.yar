rule TTP_XOR_QUAD_CurrentVersionRun_6433 {
  strings:
    $key_6433 = { 37 5c [2] 13 52 [2] 38 7e [2] 16 5c [2] 02 47 [2] 0d 5d [2] 13 40 [2] 11 41 [2] 0a 47 [2] 16 40 [2] 0a 6f }

  condition:
    any of them
}