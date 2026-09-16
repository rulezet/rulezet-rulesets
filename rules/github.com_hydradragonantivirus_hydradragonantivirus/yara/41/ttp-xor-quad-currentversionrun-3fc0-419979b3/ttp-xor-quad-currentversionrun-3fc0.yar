rule TTP_XOR_QUAD_CurrentVersionRun_3fc0 {
  strings:
    $key_3fc0 = { 6c af [2] 48 a1 [2] 63 8d [2] 4d af [2] 59 b4 [2] 56 ae [2] 48 b3 [2] 4a b2 [2] 51 b4 [2] 4d b3 [2] 51 9c }

  condition:
    any of them
}