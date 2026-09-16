rule TTP_XOR_QUAD_CurrentVersionRun_2bc1 {
  strings:
    $key_2bc1 = { 78 ae [2] 5c a0 [2] 77 8c [2] 59 ae [2] 4d b5 [2] 42 af [2] 5c b2 [2] 5e b3 [2] 45 b5 [2] 59 b2 [2] 45 9d }

  condition:
    any of them
}