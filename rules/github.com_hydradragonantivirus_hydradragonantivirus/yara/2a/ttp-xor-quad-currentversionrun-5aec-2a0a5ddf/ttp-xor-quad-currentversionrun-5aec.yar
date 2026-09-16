rule TTP_XOR_QUAD_CurrentVersionRun_5aec {
  strings:
    $key_5aec = { 09 83 [2] 2d 8d [2] 06 a1 [2] 28 83 [2] 3c 98 [2] 33 82 [2] 2d 9f [2] 2f 9e [2] 34 98 [2] 28 9f [2] 34 b0 }

  condition:
    any of them
}