rule TTP_XOR_QUAD_CurrentVersionRun_3e4c {
  strings:
    $key_3e4c = { 6d 23 [2] 49 2d [2] 62 01 [2] 4c 23 [2] 58 38 [2] 57 22 [2] 49 3f [2] 4b 3e [2] 50 38 [2] 4c 3f [2] 50 10 }

  condition:
    any of them
}