rule TTP_XOR_QUAD_CurrentVersionRun_7310 {
  strings:
    $key_7310 = { 20 7f [2] 04 71 [2] 2f 5d [2] 01 7f [2] 15 64 [2] 1a 7e [2] 04 63 [2] 06 62 [2] 1d 64 [2] 01 63 [2] 1d 4c }

  condition:
    any of them
}