rule TTP_XOR_QUAD_CurrentVersionRun_5310 {
  strings:
    $key_5310 = { 00 7f [2] 24 71 [2] 0f 5d [2] 21 7f [2] 35 64 [2] 3a 7e [2] 24 63 [2] 26 62 [2] 3d 64 [2] 21 63 [2] 3d 4c }

  condition:
    any of them
}