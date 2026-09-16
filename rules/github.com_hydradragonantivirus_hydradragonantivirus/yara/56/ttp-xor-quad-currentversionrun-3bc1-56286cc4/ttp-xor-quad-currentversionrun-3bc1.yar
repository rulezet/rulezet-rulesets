rule TTP_XOR_QUAD_CurrentVersionRun_3bc1 {
  strings:
    $key_3bc1 = { 68 ae [2] 4c a0 [2] 67 8c [2] 49 ae [2] 5d b5 [2] 52 af [2] 4c b2 [2] 4e b3 [2] 55 b5 [2] 49 b2 [2] 55 9d }

  condition:
    any of them
}