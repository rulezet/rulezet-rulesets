rule TTP_XOR_QUAD_CurrentVersionRun_aae1 {
  strings:
    $key_aae1 = { f9 8e [2] dd 80 [2] f6 ac [2] d8 8e [2] cc 95 [2] c3 8f [2] dd 92 [2] df 93 [2] c4 95 [2] d8 92 [2] c4 bd }

  condition:
    any of them
}