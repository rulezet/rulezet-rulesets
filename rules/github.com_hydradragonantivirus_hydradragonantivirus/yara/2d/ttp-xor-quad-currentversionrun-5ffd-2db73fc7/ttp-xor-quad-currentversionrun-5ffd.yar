rule TTP_XOR_QUAD_CurrentVersionRun_5ffd {
  strings:
    $key_5ffd = { 0c 92 [2] 28 9c [2] 03 b0 [2] 2d 92 [2] 39 89 [2] 36 93 [2] 28 8e [2] 2a 8f [2] 31 89 [2] 2d 8e [2] 31 a1 }

  condition:
    any of them
}