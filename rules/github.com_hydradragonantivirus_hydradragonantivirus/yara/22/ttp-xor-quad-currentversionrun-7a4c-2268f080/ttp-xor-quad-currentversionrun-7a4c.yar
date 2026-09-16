rule TTP_XOR_QUAD_CurrentVersionRun_7a4c {
  strings:
    $key_7a4c = { 29 23 [2] 0d 2d [2] 26 01 [2] 08 23 [2] 1c 38 [2] 13 22 [2] 0d 3f [2] 0f 3e [2] 14 38 [2] 08 3f [2] 14 10 }

  condition:
    any of them
}