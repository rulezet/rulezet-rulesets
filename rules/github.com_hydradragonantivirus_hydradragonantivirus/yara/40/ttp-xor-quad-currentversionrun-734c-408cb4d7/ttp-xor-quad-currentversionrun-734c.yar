rule TTP_XOR_QUAD_CurrentVersionRun_734c {
  strings:
    $key_734c = { 20 23 [2] 04 2d [2] 2f 01 [2] 01 23 [2] 15 38 [2] 1a 22 [2] 04 3f [2] 06 3e [2] 1d 38 [2] 01 3f [2] 1d 10 }

  condition:
    any of them
}