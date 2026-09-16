rule TTP_XOR_QUAD_CurrentVersionRun_004c {
  strings:
    $key_004c = { 53 23 [2] 77 2d [2] 5c 01 [2] 72 23 [2] 66 38 [2] 69 22 [2] 77 3f [2] 75 3e [2] 6e 38 [2] 72 3f [2] 6e 10 }

  condition:
    any of them
}