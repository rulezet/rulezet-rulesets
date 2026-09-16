rule TTP_XOR_QUAD_CurrentVersionRun_e7ec {
  strings:
    $key_e7ec = { b4 83 [2] 90 8d [2] bb a1 [2] 95 83 [2] 81 98 [2] 8e 82 [2] 90 9f [2] 92 9e [2] 89 98 [2] 95 9f [2] 89 b0 }

  condition:
    any of them
}