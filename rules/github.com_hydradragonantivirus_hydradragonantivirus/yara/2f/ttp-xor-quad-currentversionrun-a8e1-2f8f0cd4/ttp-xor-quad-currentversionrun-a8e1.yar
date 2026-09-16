rule TTP_XOR_QUAD_CurrentVersionRun_a8e1 {
  strings:
    $key_a8e1 = { fb 8e [2] df 80 [2] f4 ac [2] da 8e [2] ce 95 [2] c1 8f [2] df 92 [2] dd 93 [2] c6 95 [2] da 92 [2] c6 bd }

  condition:
    any of them
}