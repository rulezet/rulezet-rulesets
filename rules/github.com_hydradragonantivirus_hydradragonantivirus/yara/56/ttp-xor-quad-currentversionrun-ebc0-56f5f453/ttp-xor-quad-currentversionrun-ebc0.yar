rule TTP_XOR_QUAD_CurrentVersionRun_ebc0 {
  strings:
    $key_ebc0 = { b8 af [2] 9c a1 [2] b7 8d [2] 99 af [2] 8d b4 [2] 82 ae [2] 9c b3 [2] 9e b2 [2] 85 b4 [2] 99 b3 [2] 85 9c }

  condition:
    any of them
}