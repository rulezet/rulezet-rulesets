rule TTP_XOR_QUAD_CurrentVersionRun_e700 {
  strings:
    $key_e700 = { b4 6f [2] 90 61 [2] bb 4d [2] 95 6f [2] 81 74 [2] 8e 6e [2] 90 73 [2] 92 72 [2] 89 74 [2] 95 73 [2] 89 5c }

  condition:
    any of them
}