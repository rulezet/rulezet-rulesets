rule TTP_XOR_QUAD_CurrentVersionRun_bbe1 {
  strings:
    $key_bbe1 = { e8 8e [2] cc 80 [2] e7 ac [2] c9 8e [2] dd 95 [2] d2 8f [2] cc 92 [2] ce 93 [2] d5 95 [2] c9 92 [2] d5 bd }

  condition:
    any of them
}