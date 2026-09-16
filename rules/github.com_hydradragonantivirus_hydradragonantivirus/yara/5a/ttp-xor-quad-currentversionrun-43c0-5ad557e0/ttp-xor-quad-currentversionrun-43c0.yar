rule TTP_XOR_QUAD_CurrentVersionRun_43c0 {
  strings:
    $key_43c0 = { 10 af [2] 34 a1 [2] 1f 8d [2] 31 af [2] 25 b4 [2] 2a ae [2] 34 b3 [2] 36 b2 [2] 2d b4 [2] 31 b3 [2] 2d 9c }

  condition:
    any of them
}