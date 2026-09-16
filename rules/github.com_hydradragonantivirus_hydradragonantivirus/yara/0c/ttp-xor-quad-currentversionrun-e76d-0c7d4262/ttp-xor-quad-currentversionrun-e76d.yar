rule TTP_XOR_QUAD_CurrentVersionRun_e76d {
  strings:
    $key_e76d = { b4 02 [2] 90 0c [2] bb 20 [2] 95 02 [2] 81 19 [2] 8e 03 [2] 90 1e [2] 92 1f [2] 89 19 [2] 95 1e [2] 89 31 }

  condition:
    any of them
}