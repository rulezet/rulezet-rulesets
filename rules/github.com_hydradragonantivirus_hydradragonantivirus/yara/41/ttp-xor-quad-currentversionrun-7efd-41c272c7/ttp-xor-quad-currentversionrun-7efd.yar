rule TTP_XOR_QUAD_CurrentVersionRun_7efd {
  strings:
    $key_7efd = { 2d 92 [2] 09 9c [2] 22 b0 [2] 0c 92 [2] 18 89 [2] 17 93 [2] 09 8e [2] 0b 8f [2] 10 89 [2] 0c 8e [2] 10 a1 }

  condition:
    any of them
}