rule TTP_XOR_QUAD_CurrentVersionRun_eedb {
  strings:
    $key_eedb = { bd b4 [2] 99 ba [2] b2 96 [2] 9c b4 [2] 88 af [2] 87 b5 [2] 99 a8 [2] 9b a9 [2] 80 af [2] 9c a8 [2] 80 87 }

  condition:
    any of them
}