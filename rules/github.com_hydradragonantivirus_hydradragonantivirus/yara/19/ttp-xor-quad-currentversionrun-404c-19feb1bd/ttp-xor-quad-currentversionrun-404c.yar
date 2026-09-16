rule TTP_XOR_QUAD_CurrentVersionRun_404c {
  strings:
    $key_404c = { 13 23 [2] 37 2d [2] 1c 01 [2] 32 23 [2] 26 38 [2] 29 22 [2] 37 3f [2] 35 3e [2] 2e 38 [2] 32 3f [2] 2e 10 }

  condition:
    any of them
}