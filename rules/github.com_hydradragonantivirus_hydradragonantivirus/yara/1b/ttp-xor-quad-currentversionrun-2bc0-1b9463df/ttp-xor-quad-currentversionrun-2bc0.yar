rule TTP_XOR_QUAD_CurrentVersionRun_2bc0 {
  strings:
    $key_2bc0 = { 78 af [2] 5c a1 [2] 77 8d [2] 59 af [2] 4d b4 [2] 42 ae [2] 5c b3 [2] 5e b2 [2] 45 b4 [2] 59 b3 [2] 45 9c }

  condition:
    any of them
}