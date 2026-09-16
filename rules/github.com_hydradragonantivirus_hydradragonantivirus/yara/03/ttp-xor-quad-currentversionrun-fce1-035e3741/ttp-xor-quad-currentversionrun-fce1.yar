rule TTP_XOR_QUAD_CurrentVersionRun_fce1 {
  strings:
    $key_fce1 = { af 8e [2] 8b 80 [2] a0 ac [2] 8e 8e [2] 9a 95 [2] 95 8f [2] 8b 92 [2] 89 93 [2] 92 95 [2] 8e 92 [2] 92 bd }

  condition:
    any of them
}