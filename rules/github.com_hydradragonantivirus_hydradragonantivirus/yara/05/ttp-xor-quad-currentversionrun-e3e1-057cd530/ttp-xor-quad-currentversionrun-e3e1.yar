rule TTP_XOR_QUAD_CurrentVersionRun_e3e1 {
  strings:
    $key_e3e1 = { b0 8e [2] 94 80 [2] bf ac [2] 91 8e [2] 85 95 [2] 8a 8f [2] 94 92 [2] 96 93 [2] 8d 95 [2] 91 92 [2] 8d bd }

  condition:
    any of them
}