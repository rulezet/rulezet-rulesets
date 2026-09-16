rule TTP_XOR_QUAD_CurrentVersionRun_4310 {
  strings:
    $key_4310 = { 10 7f [2] 34 71 [2] 1f 5d [2] 31 7f [2] 25 64 [2] 2a 7e [2] 34 63 [2] 36 62 [2] 2d 64 [2] 31 63 [2] 2d 4c }

  condition:
    any of them
}