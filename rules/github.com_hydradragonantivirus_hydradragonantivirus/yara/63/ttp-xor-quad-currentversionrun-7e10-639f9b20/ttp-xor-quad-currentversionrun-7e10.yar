rule TTP_XOR_QUAD_CurrentVersionRun_7e10 {
  strings:
    $key_7e10 = { 2d 7f [2] 09 71 [2] 22 5d [2] 0c 7f [2] 18 64 [2] 17 7e [2] 09 63 [2] 0b 62 [2] 10 64 [2] 0c 63 [2] 10 4c }

  condition:
    any of them
}