rule TTP_XOR_QUAD_CurrentVersionRun_4b1d {
  strings:
    $key_4b1d = { 18 72 [2] 3c 7c [2] 17 50 [2] 39 72 [2] 2d 69 [2] 22 73 [2] 3c 6e [2] 3e 6f [2] 25 69 [2] 39 6e [2] 25 41 }

  condition:
    any of them
}