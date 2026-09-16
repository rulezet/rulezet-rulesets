rule TTP_XOR_QUAD_CurrentVersionRun_31e1 {
  strings:
    $key_31e1 = { 62 8e [2] 46 80 [2] 6d ac [2] 43 8e [2] 57 95 [2] 58 8f [2] 46 92 [2] 44 93 [2] 5f 95 [2] 43 92 [2] 5f bd }

  condition:
    any of them
}