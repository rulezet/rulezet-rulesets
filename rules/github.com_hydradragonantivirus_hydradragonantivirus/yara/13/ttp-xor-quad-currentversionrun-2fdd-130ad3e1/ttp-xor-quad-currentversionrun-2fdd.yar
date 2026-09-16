rule TTP_XOR_QUAD_CurrentVersionRun_2fdd {
  strings:
    $key_2fdd = { 7c b2 [2] 58 bc [2] 73 90 [2] 5d b2 [2] 49 a9 [2] 46 b3 [2] 58 ae [2] 5a af [2] 41 a9 [2] 5d ae [2] 41 81 }

  condition:
    any of them
}