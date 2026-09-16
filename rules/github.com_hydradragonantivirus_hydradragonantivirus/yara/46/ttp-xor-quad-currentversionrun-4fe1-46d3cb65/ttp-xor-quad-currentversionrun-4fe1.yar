rule TTP_XOR_QUAD_CurrentVersionRun_4fe1 {
  strings:
    $key_4fe1 = { 1c 8e [2] 38 80 [2] 13 ac [2] 3d 8e [2] 29 95 [2] 26 8f [2] 38 92 [2] 3a 93 [2] 21 95 [2] 3d 92 [2] 21 bd }

  condition:
    any of them
}