rule TTP_XOR_QUAD_CurrentVersionRun_1efd {
  strings:
    $key_1efd = { 4d 92 [2] 69 9c [2] 42 b0 [2] 6c 92 [2] 78 89 [2] 77 93 [2] 69 8e [2] 6b 8f [2] 70 89 [2] 6c 8e [2] 70 a1 }

  condition:
    any of them
}