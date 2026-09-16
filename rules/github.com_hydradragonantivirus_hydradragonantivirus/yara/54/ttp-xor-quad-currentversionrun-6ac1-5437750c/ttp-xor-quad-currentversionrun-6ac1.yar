rule TTP_XOR_QUAD_CurrentVersionRun_6ac1 {
  strings:
    $key_6ac1 = { 39 ae [2] 1d a0 [2] 36 8c [2] 18 ae [2] 0c b5 [2] 03 af [2] 1d b2 [2] 1f b3 [2] 04 b5 [2] 18 b2 [2] 04 9d }

  condition:
    any of them
}