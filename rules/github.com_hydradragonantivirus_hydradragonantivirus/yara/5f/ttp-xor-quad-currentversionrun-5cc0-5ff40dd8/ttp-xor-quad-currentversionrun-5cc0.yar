rule TTP_XOR_QUAD_CurrentVersionRun_5cc0 {
  strings:
    $key_5cc0 = { 0f af [2] 2b a1 [2] 00 8d [2] 2e af [2] 3a b4 [2] 35 ae [2] 2b b3 [2] 29 b2 [2] 32 b4 [2] 2e b3 [2] 32 9c }

  condition:
    any of them
}