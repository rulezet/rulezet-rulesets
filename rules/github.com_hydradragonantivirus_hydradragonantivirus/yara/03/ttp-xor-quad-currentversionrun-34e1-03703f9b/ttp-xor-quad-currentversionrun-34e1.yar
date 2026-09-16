rule TTP_XOR_QUAD_CurrentVersionRun_34e1 {
  strings:
    $key_34e1 = { 67 8e [2] 43 80 [2] 68 ac [2] 46 8e [2] 52 95 [2] 5d 8f [2] 43 92 [2] 41 93 [2] 5a 95 [2] 46 92 [2] 5a bd }

  condition:
    any of them
}