rule TTP_XOR_QUAD_CurrentVersionRun_e71c {
  strings:
    $key_e71c = { b4 73 [2] 90 7d [2] bb 51 [2] 95 73 [2] 81 68 [2] 8e 72 [2] 90 6f [2] 92 6e [2] 89 68 [2] 95 6f [2] 89 40 }

  condition:
    any of them
}