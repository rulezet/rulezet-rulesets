rule TTP_XOR_QUAD_CurrentVersionRun_0ac1 {
  strings:
    $key_0ac1 = { 59 ae [2] 7d a0 [2] 56 8c [2] 78 ae [2] 6c b5 [2] 63 af [2] 7d b2 [2] 7f b3 [2] 64 b5 [2] 78 b2 [2] 64 9d }

  condition:
    any of them
}