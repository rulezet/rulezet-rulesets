rule TTP_XOR_QUAD_CurrentVersionRun_59c0 {
  strings:
    $key_59c0 = { 0a af [2] 2e a1 [2] 05 8d [2] 2b af [2] 3f b4 [2] 30 ae [2] 2e b3 [2] 2c b2 [2] 37 b4 [2] 2b b3 [2] 37 9c }

  condition:
    any of them
}