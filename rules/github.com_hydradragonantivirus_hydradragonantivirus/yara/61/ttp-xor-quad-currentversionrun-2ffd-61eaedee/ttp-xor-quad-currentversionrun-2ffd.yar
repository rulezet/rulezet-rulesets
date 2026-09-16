rule TTP_XOR_QUAD_CurrentVersionRun_2ffd {
  strings:
    $key_2ffd = { 7c 92 [2] 58 9c [2] 73 b0 [2] 5d 92 [2] 49 89 [2] 46 93 [2] 58 8e [2] 5a 8f [2] 41 89 [2] 5d 8e [2] 41 a1 }

  condition:
    any of them
}