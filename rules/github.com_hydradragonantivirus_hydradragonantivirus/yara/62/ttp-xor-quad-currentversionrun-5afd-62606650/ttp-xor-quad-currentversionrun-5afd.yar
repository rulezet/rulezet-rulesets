rule TTP_XOR_QUAD_CurrentVersionRun_5afd {
  strings:
    $key_5afd = { 09 92 [2] 2d 9c [2] 06 b0 [2] 28 92 [2] 3c 89 [2] 33 93 [2] 2d 8e [2] 2f 8f [2] 34 89 [2] 28 8e [2] 34 a1 }

  condition:
    any of them
}