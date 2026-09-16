rule TTP_XOR_QUAD_CurrentVersionRun_7e1d {
  strings:
    $key_7e1d = { 2d 72 [2] 09 7c [2] 22 50 [2] 0c 72 [2] 18 69 [2] 17 73 [2] 09 6e [2] 0b 6f [2] 10 69 [2] 0c 6e [2] 10 41 }

  condition:
    any of them
}