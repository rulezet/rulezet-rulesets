rule TTP_XOR_QUAD_CurrentVersionRun_1cc0 {
  strings:
    $key_1cc0 = { 4f af [2] 6b a1 [2] 40 8d [2] 6e af [2] 7a b4 [2] 75 ae [2] 6b b3 [2] 69 b2 [2] 72 b4 [2] 6e b3 [2] 72 9c }

  condition:
    any of them
}