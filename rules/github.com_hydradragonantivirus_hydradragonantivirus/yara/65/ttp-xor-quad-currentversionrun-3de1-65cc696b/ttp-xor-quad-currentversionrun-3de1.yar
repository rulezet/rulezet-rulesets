rule TTP_XOR_QUAD_CurrentVersionRun_3de1 {
  strings:
    $key_3de1 = { 6e 8e [2] 4a 80 [2] 61 ac [2] 4f 8e [2] 5b 95 [2] 54 8f [2] 4a 92 [2] 48 93 [2] 53 95 [2] 4f 92 [2] 53 bd }

  condition:
    any of them
}