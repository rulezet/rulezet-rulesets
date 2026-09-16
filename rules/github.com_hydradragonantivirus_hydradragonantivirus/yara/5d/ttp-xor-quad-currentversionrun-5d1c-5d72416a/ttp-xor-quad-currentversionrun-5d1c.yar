rule TTP_XOR_QUAD_CurrentVersionRun_5d1c {
  strings:
    $key_5d1c = { 0e 73 [2] 2a 7d [2] 01 51 [2] 2f 73 [2] 3b 68 [2] 34 72 [2] 2a 6f [2] 28 6e [2] 33 68 [2] 2f 6f [2] 33 40 }

  condition:
    any of them
}