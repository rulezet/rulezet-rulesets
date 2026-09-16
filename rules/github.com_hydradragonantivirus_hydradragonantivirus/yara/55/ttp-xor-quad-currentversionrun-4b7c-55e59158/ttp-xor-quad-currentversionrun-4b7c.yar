rule TTP_XOR_QUAD_CurrentVersionRun_4b7c {
  strings:
    $key_4b7c = { 18 13 [2] 3c 1d [2] 17 31 [2] 39 13 [2] 2d 08 [2] 22 12 [2] 3c 0f [2] 3e 0e [2] 25 08 [2] 39 0f [2] 25 20 }

  condition:
    any of them
}