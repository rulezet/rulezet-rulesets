rule TTP_XOR_QUAD_CurrentVersionRun_e5c0 {
  strings:
    $key_e5c0 = { b6 af [2] 92 a1 [2] b9 8d [2] 97 af [2] 83 b4 [2] 8c ae [2] 92 b3 [2] 90 b2 [2] 8b b4 [2] 97 b3 [2] 8b 9c }

  condition:
    any of them
}