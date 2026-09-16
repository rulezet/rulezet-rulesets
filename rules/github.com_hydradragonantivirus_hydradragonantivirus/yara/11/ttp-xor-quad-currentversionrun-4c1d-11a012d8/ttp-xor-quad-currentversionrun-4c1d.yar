rule TTP_XOR_QUAD_CurrentVersionRun_4c1d {
  strings:
    $key_4c1d = { 1f 72 [2] 3b 7c [2] 10 50 [2] 3e 72 [2] 2a 69 [2] 25 73 [2] 3b 6e [2] 39 6f [2] 22 69 [2] 3e 6e [2] 22 41 }

  condition:
    any of them
}