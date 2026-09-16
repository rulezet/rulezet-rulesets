rule TTP_XOR_QUAD_CurrentVersionRun_01e1 {
  strings:
    $key_01e1 = { 52 8e [2] 76 80 [2] 5d ac [2] 73 8e [2] 67 95 [2] 68 8f [2] 76 92 [2] 74 93 [2] 6f 95 [2] 73 92 [2] 6f bd }

  condition:
    any of them
}