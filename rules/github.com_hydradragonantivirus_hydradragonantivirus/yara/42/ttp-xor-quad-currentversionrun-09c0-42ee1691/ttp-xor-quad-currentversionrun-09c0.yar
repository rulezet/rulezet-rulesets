rule TTP_XOR_QUAD_CurrentVersionRun_09c0 {
  strings:
    $key_09c0 = { 5a af [2] 7e a1 [2] 55 8d [2] 7b af [2] 6f b4 [2] 60 ae [2] 7e b3 [2] 7c b2 [2] 67 b4 [2] 7b b3 [2] 67 9c }

  condition:
    any of them
}