rule TTP_XOR_QUAD_CurrentVersionRun_bfe1 {
  strings:
    $key_bfe1 = { ec 8e [2] c8 80 [2] e3 ac [2] cd 8e [2] d9 95 [2] d6 8f [2] c8 92 [2] ca 93 [2] d1 95 [2] cd 92 [2] d1 bd }

  condition:
    any of them
}