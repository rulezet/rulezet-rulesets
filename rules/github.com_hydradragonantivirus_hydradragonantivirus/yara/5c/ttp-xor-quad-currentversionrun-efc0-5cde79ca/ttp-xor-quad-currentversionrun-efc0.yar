rule TTP_XOR_QUAD_CurrentVersionRun_efc0 {
  strings:
    $key_efc0 = { bc af [2] 98 a1 [2] b3 8d [2] 9d af [2] 89 b4 [2] 86 ae [2] 98 b3 [2] 9a b2 [2] 81 b4 [2] 9d b3 [2] 81 9c }

  condition:
    any of them
}