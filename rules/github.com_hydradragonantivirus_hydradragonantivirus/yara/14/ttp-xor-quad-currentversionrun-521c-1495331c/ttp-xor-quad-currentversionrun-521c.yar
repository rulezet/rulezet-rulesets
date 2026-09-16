rule TTP_XOR_QUAD_CurrentVersionRun_521c {
  strings:
    $key_521c = { 01 73 [2] 25 7d [2] 0e 51 [2] 20 73 [2] 34 68 [2] 3b 72 [2] 25 6f [2] 27 6e [2] 3c 68 [2] 20 6f [2] 3c 40 }

  condition:
    any of them
}