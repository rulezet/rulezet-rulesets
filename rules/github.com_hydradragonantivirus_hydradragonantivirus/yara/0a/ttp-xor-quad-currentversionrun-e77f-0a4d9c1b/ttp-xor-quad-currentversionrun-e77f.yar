rule TTP_XOR_QUAD_CurrentVersionRun_e77f {
  strings:
    $key_e77f = { b4 10 [2] 90 1e [2] bb 32 [2] 95 10 [2] 81 0b [2] 8e 11 [2] 90 0c [2] 92 0d [2] 89 0b [2] 95 0c [2] 89 23 }

  condition:
    any of them
}