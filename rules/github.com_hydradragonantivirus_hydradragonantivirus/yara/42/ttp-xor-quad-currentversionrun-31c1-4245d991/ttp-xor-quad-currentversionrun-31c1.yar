rule TTP_XOR_QUAD_CurrentVersionRun_31c1 {
  strings:
    $key_31c1 = { 62 ae [2] 46 a0 [2] 6d 8c [2] 43 ae [2] 57 b5 [2] 58 af [2] 46 b2 [2] 44 b3 [2] 5f b5 [2] 43 b2 [2] 5f 9d }

  condition:
    any of them
}