rule TTP_XOR_QUAD_CurrentVersionRun_29d3 {
  strings:
    $key_29d3 = { 7a bc [2] 5e b2 [2] 75 9e [2] 5b bc [2] 4f a7 [2] 40 bd [2] 5e a0 [2] 5c a1 [2] 47 a7 [2] 5b a0 [2] 47 8f }

  condition:
    any of them
}