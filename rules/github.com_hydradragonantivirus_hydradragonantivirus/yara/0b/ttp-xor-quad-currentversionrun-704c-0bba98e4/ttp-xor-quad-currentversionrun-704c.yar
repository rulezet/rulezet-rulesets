rule TTP_XOR_QUAD_CurrentVersionRun_704c {
  strings:
    $key_704c = { 23 23 [2] 07 2d [2] 2c 01 [2] 02 23 [2] 16 38 [2] 19 22 [2] 07 3f [2] 05 3e [2] 1e 38 [2] 02 3f [2] 1e 10 }

  condition:
    any of them
}