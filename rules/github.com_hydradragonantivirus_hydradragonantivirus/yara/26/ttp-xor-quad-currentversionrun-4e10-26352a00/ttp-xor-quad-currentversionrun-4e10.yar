rule TTP_XOR_QUAD_CurrentVersionRun_4e10 {
  strings:
    $key_4e10 = { 1d 7f [2] 39 71 [2] 12 5d [2] 3c 7f [2] 28 64 [2] 27 7e [2] 39 63 [2] 3b 62 [2] 20 64 [2] 3c 63 [2] 20 4c }

  condition:
    any of them
}