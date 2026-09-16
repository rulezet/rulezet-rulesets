rule TTP_XOR_QUAD_CurrentVersionRun_6310 {
  strings:
    $key_6310 = { 30 7f [2] 14 71 [2] 3f 5d [2] 11 7f [2] 05 64 [2] 0a 7e [2] 14 63 [2] 16 62 [2] 0d 64 [2] 11 63 [2] 0d 4c }

  condition:
    any of them
}