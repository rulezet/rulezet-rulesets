rule TTP_XOR_QUAD_CurrentVersionRun_6fdd {
  strings:
    $key_6fdd = { 3c b2 [2] 18 bc [2] 33 90 [2] 1d b2 [2] 09 a9 [2] 06 b3 [2] 18 ae [2] 1a af [2] 01 a9 [2] 1d ae [2] 01 81 }

  condition:
    any of them
}