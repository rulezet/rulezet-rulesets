rule TTP_XOR_QUAD_CurrentVersionRun_0c4c {
  strings:
    $key_0c4c = { 5f 23 [2] 7b 2d [2] 50 01 [2] 7e 23 [2] 6a 38 [2] 65 22 [2] 7b 3f [2] 79 3e [2] 62 38 [2] 7e 3f [2] 62 10 }

  condition:
    any of them
}