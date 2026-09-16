rule TTP_XOR_QUAD_CurrentVersionRun_b9e1 {
  strings:
    $key_b9e1 = { ea 8e [2] ce 80 [2] e5 ac [2] cb 8e [2] df 95 [2] d0 8f [2] ce 92 [2] cc 93 [2] d7 95 [2] cb 92 [2] d7 bd }

  condition:
    any of them
}