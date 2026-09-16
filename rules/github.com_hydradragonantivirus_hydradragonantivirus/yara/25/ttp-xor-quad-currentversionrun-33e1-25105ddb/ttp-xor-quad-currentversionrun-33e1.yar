rule TTP_XOR_QUAD_CurrentVersionRun_33e1 {
  strings:
    $key_33e1 = { 60 8e [2] 44 80 [2] 6f ac [2] 41 8e [2] 55 95 [2] 5a 8f [2] 44 92 [2] 46 93 [2] 5d 95 [2] 41 92 [2] 5d bd }

  condition:
    any of them
}