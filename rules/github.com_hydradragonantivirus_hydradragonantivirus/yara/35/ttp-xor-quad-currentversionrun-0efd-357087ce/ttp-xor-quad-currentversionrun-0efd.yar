rule TTP_XOR_QUAD_CurrentVersionRun_0efd {
  strings:
    $key_0efd = { 5d 92 [2] 79 9c [2] 52 b0 [2] 7c 92 [2] 68 89 [2] 67 93 [2] 79 8e [2] 7b 8f [2] 60 89 [2] 7c 8e [2] 60 a1 }

  condition:
    any of them
}