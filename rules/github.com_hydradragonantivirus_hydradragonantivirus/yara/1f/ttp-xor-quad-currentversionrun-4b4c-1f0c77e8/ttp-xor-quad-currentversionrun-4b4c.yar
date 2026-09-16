rule TTP_XOR_QUAD_CurrentVersionRun_4b4c {
  strings:
    $key_4b4c = { 18 23 [2] 3c 2d [2] 17 01 [2] 39 23 [2] 2d 38 [2] 22 22 [2] 3c 3f [2] 3e 3e [2] 25 38 [2] 39 3f [2] 25 10 }

  condition:
    any of them
}