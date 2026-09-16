rule TTP_XOR_QUAD_CurrentVersionRun_7b1c {
  strings:
    $key_7b1c = { 28 73 [2] 0c 7d [2] 27 51 [2] 09 73 [2] 1d 68 [2] 12 72 [2] 0c 6f [2] 0e 6e [2] 15 68 [2] 09 6f [2] 15 40 }

  condition:
    any of them
}