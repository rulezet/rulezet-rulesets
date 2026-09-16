rule TTP_XOR_QUAD_CurrentVersionRun_abe1 {
  strings:
    $key_abe1 = { f8 8e [2] dc 80 [2] f7 ac [2] d9 8e [2] cd 95 [2] c2 8f [2] dc 92 [2] de 93 [2] c5 95 [2] d9 92 [2] c5 bd }

  condition:
    any of them
}