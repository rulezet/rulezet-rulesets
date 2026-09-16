rule TTP_XOR_QUAD_CurrentVersionRun_efc5 {
  strings:
    $key_efc5 = { bc aa [2] 98 a4 [2] b3 88 [2] 9d aa [2] 89 b1 [2] 86 ab [2] 98 b6 [2] 9a b7 [2] 81 b1 [2] 9d b6 [2] 81 99 }

  condition:
    any of them
}