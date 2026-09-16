rule TTP_XOR_QUAD_CurrentVersionRun_3efd {
  strings:
    $key_3efd = { 6d 92 [2] 49 9c [2] 62 b0 [2] 4c 92 [2] 58 89 [2] 57 93 [2] 49 8e [2] 4b 8f [2] 50 89 [2] 4c 8e [2] 50 a1 }

  condition:
    any of them
}