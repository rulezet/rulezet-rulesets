rule TTP_XOR_QUAD_CurrentVersionRun_6cc0 {
  strings:
    $key_6cc0 = { 3f af [2] 1b a1 [2] 30 8d [2] 1e af [2] 0a b4 [2] 05 ae [2] 1b b3 [2] 19 b2 [2] 02 b4 [2] 1e b3 [2] 02 9c }

  condition:
    any of them
}