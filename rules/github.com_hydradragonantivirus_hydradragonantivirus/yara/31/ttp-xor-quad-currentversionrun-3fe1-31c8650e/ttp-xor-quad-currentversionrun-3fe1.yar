rule TTP_XOR_QUAD_CurrentVersionRun_3fe1 {
  strings:
    $key_3fe1 = { 6c 8e [2] 48 80 [2] 63 ac [2] 4d 8e [2] 59 95 [2] 56 8f [2] 48 92 [2] 4a 93 [2] 51 95 [2] 4d 92 [2] 51 bd }

  condition:
    any of them
}