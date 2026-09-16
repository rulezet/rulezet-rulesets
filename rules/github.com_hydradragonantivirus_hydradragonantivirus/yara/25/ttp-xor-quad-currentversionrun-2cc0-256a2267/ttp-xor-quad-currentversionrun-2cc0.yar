rule TTP_XOR_QUAD_CurrentVersionRun_2cc0 {
  strings:
    $key_2cc0 = { 7f af [2] 5b a1 [2] 70 8d [2] 5e af [2] 4a b4 [2] 45 ae [2] 5b b3 [2] 59 b2 [2] 42 b4 [2] 5e b3 [2] 42 9c }

  condition:
    any of them
}