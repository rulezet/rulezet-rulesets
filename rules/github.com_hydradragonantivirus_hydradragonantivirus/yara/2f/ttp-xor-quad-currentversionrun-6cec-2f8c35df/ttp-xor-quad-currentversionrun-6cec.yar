rule TTP_XOR_QUAD_CurrentVersionRun_6cec {
  strings:
    $key_6cec = { 3f 83 [2] 1b 8d [2] 30 a1 [2] 1e 83 [2] 0a 98 [2] 05 82 [2] 1b 9f [2] 19 9e [2] 02 98 [2] 1e 9f [2] 02 b0 }

  condition:
    any of them
}