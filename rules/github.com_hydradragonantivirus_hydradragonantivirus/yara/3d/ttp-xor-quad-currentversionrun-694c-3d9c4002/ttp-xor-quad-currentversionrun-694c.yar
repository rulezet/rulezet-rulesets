rule TTP_XOR_QUAD_CurrentVersionRun_694c {
  strings:
    $key_694c = { 3a 23 [2] 1e 2d [2] 35 01 [2] 1b 23 [2] 0f 38 [2] 00 22 [2] 1e 3f [2] 1c 3e [2] 07 38 [2] 1b 3f [2] 07 10 }

  condition:
    any of them
}