rule TTP_XOR_QUAD_CurrentVersionRun_f0ec {
  strings:
    $key_f0ec = { a3 83 [2] 87 8d [2] ac a1 [2] 82 83 [2] 96 98 [2] 99 82 [2] 87 9f [2] 85 9e [2] 9e 98 [2] 82 9f [2] 9e b0 }

  condition:
    any of them
}