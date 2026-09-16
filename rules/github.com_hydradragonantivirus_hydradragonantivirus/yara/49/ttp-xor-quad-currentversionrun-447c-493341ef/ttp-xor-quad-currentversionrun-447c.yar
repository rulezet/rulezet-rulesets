rule TTP_XOR_QUAD_CurrentVersionRun_447c {
  strings:
    $key_447c = { 17 13 [2] 33 1d [2] 18 31 [2] 36 13 [2] 22 08 [2] 2d 12 [2] 33 0f [2] 31 0e [2] 2a 08 [2] 36 0f [2] 2a 20 }

  condition:
    any of them
}