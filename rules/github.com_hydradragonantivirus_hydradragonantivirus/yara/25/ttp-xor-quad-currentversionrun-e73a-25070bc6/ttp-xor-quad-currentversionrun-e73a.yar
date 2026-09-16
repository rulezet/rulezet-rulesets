rule TTP_XOR_QUAD_CurrentVersionRun_e73a {
  strings:
    $key_e73a = { b4 55 [2] 90 5b [2] bb 77 [2] 95 55 [2] 81 4e [2] 8e 54 [2] 90 49 [2] 92 48 [2] 89 4e [2] 95 49 [2] 89 66 }

  condition:
    any of them
}