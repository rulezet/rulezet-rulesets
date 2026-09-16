rule TTP_XOR_QUAD_CurrentVersionRun_11e1 {
  strings:
    $key_11e1 = { 42 8e [2] 66 80 [2] 4d ac [2] 63 8e [2] 77 95 [2] 78 8f [2] 66 92 [2] 64 93 [2] 7f 95 [2] 63 92 [2] 7f bd }

  condition:
    any of them
}