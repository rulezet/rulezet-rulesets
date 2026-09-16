rule TTP_XOR_QUAD_CurrentVersionRun_09c1 {
  strings:
    $key_09c1 = { 5a ae [2] 7e a0 [2] 55 8c [2] 7b ae [2] 6f b5 [2] 60 af [2] 7e b2 [2] 7c b3 [2] 67 b5 [2] 7b b2 [2] 67 9d }

  condition:
    any of them
}