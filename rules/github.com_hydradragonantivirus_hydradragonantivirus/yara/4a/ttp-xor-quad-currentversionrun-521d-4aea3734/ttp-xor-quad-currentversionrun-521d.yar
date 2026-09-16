rule TTP_XOR_QUAD_CurrentVersionRun_521d {
  strings:
    $key_521d = { 01 72 [2] 25 7c [2] 0e 50 [2] 20 72 [2] 34 69 [2] 3b 73 [2] 25 6e [2] 27 6f [2] 3c 69 [2] 20 6e [2] 3c 41 }

  condition:
    any of them
}