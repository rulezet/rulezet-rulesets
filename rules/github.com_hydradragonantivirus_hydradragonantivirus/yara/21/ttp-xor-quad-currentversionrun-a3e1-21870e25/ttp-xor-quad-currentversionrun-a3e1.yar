rule TTP_XOR_QUAD_CurrentVersionRun_a3e1 {
  strings:
    $key_a3e1 = { f0 8e [2] d4 80 [2] ff ac [2] d1 8e [2] c5 95 [2] ca 8f [2] d4 92 [2] d6 93 [2] cd 95 [2] d1 92 [2] cd bd }

  condition:
    any of them
}