rule TTP_XOR_QUAD_CurrentVersionRun_63c0 {
  strings:
    $key_63c0 = { 30 af [2] 14 a1 [2] 3f 8d [2] 11 af [2] 05 b4 [2] 0a ae [2] 14 b3 [2] 16 b2 [2] 0d b4 [2] 11 b3 [2] 0d 9c }

  condition:
    any of them
}