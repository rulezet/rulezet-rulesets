rule TTP_XOR_QUAD_CurrentVersionRun_e73f {
  strings:
    $key_e73f = { b4 50 [2] 90 5e [2] bb 72 [2] 95 50 [2] 81 4b [2] 8e 51 [2] 90 4c [2] 92 4d [2] 89 4b [2] 95 4c [2] 89 63 }

  condition:
    any of them
}