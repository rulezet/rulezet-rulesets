rule TTP_XOR_QUAD_CurrentVersionRun_efe1 {
  strings:
    $key_efe1 = { bc 8e [2] 98 80 [2] b3 ac [2] 9d 8e [2] 89 95 [2] 86 8f [2] 98 92 [2] 9a 93 [2] 81 95 [2] 9d 92 [2] 81 bd }

  condition:
    any of them
}