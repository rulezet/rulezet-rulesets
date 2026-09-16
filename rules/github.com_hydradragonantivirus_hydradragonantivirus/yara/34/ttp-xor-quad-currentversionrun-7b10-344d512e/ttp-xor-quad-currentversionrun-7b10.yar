rule TTP_XOR_QUAD_CurrentVersionRun_7b10 {
  strings:
    $key_7b10 = { 28 7f [2] 0c 71 [2] 27 5d [2] 09 7f [2] 1d 64 [2] 12 7e [2] 0c 63 [2] 0e 62 [2] 15 64 [2] 09 63 [2] 15 4c }

  condition:
    any of them
}