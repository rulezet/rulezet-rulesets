rule TTP_XOR_QUAD_CurrentVersionRun_1b1d {
  strings:
    $key_1b1d = { 48 72 [2] 6c 7c [2] 47 50 [2] 69 72 [2] 7d 69 [2] 72 73 [2] 6c 6e [2] 6e 6f [2] 75 69 [2] 69 6e [2] 75 41 }

  condition:
    any of them
}