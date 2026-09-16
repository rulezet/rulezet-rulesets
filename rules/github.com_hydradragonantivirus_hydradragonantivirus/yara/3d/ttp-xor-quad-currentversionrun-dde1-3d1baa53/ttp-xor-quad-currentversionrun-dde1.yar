rule TTP_XOR_QUAD_CurrentVersionRun_dde1 {
  strings:
    $key_dde1 = { 8e 8e [2] aa 80 [2] 81 ac [2] af 8e [2] bb 95 [2] b4 8f [2] aa 92 [2] a8 93 [2] b3 95 [2] af 92 [2] b3 bd }

  condition:
    any of them
}