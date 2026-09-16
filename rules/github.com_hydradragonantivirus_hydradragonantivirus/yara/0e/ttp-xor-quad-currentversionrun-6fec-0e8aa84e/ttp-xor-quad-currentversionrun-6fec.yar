rule TTP_XOR_QUAD_CurrentVersionRun_6fec {
  strings:
    $key_6fec = { 3c 83 [2] 18 8d [2] 33 a1 [2] 1d 83 [2] 09 98 [2] 06 82 [2] 18 9f [2] 1a 9e [2] 01 98 [2] 1d 9f [2] 01 b0 }

  condition:
    any of them
}