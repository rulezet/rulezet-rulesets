rule TTP_XOR_QUAD_CurrentVersionRun_7ffd {
  strings:
    $key_7ffd = { 2c 92 [2] 08 9c [2] 23 b0 [2] 0d 92 [2] 19 89 [2] 16 93 [2] 08 8e [2] 0a 8f [2] 11 89 [2] 0d 8e [2] 11 a1 }

  condition:
    any of them
}