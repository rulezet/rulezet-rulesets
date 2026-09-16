rule TTP_XOR_QUAD_CurrentVersionRun_21c1 {
  strings:
    $key_21c1 = { 72 ae [2] 56 a0 [2] 7d 8c [2] 53 ae [2] 47 b5 [2] 48 af [2] 56 b2 [2] 54 b3 [2] 4f b5 [2] 53 b2 [2] 4f 9d }

  condition:
    any of them
}