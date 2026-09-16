rule TTP_XOR_QUAD_CurrentVersionRun_7eec {
  strings:
    $key_7eec = { 2d 83 [2] 09 8d [2] 22 a1 [2] 0c 83 [2] 18 98 [2] 17 82 [2] 09 9f [2] 0b 9e [2] 10 98 [2] 0c 9f [2] 10 b0 }

  condition:
    any of them
}