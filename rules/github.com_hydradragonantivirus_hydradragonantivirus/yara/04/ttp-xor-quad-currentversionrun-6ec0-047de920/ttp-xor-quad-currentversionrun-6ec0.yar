rule TTP_XOR_QUAD_CurrentVersionRun_6ec0 {
  strings:
    $key_6ec0 = { 3d af [2] 19 a1 [2] 32 8d [2] 1c af [2] 08 b4 [2] 07 ae [2] 19 b3 [2] 1b b2 [2] 00 b4 [2] 1c b3 [2] 00 9c }

  condition:
    any of them
}