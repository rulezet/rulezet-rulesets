rule TTP_XOR_QUAD_CurrentVersionRun_1bc1 {
  strings:
    $key_1bc1 = { 48 ae [2] 6c a0 [2] 47 8c [2] 69 ae [2] 7d b5 [2] 72 af [2] 6c b2 [2] 6e b3 [2] 75 b5 [2] 69 b2 [2] 75 9d }

  condition:
    any of them
}