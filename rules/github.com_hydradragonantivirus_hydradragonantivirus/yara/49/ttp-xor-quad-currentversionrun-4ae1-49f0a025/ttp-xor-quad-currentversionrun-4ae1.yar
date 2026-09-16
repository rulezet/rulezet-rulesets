rule TTP_XOR_QUAD_CurrentVersionRun_4ae1 {
  strings:
    $key_4ae1 = { 19 8e [2] 3d 80 [2] 16 ac [2] 38 8e [2] 2c 95 [2] 23 8f [2] 3d 92 [2] 3f 93 [2] 24 95 [2] 38 92 [2] 24 bd }

  condition:
    any of them
}