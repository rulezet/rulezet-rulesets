rule TTP_XOR_QUAD_CurrentVersionRun_7cec {
  strings:
    $key_7cec = { 2f 83 [2] 0b 8d [2] 20 a1 [2] 0e 83 [2] 1a 98 [2] 15 82 [2] 0b 9f [2] 09 9e [2] 12 98 [2] 0e 9f [2] 12 b0 }

  condition:
    any of them
}