rule TTP_XOR_QUAD_CurrentVersionRun_41e1 {
  strings:
    $key_41e1 = { 12 8e [2] 36 80 [2] 1d ac [2] 33 8e [2] 27 95 [2] 28 8f [2] 36 92 [2] 34 93 [2] 2f 95 [2] 33 92 [2] 2f bd }

  condition:
    any of them
}