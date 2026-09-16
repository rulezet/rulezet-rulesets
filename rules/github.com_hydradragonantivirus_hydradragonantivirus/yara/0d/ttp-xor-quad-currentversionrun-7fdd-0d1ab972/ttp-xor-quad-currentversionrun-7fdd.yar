rule TTP_XOR_QUAD_CurrentVersionRun_7fdd {
  strings:
    $key_7fdd = { 2c b2 [2] 08 bc [2] 23 90 [2] 0d b2 [2] 19 a9 [2] 16 b3 [2] 08 ae [2] 0a af [2] 11 a9 [2] 0d ae [2] 11 81 }

  condition:
    any of them
}