rule TTP_XOR_QUAD_CurrentVersionRun_ffc5 {
  strings:
    $key_ffc5 = { ac aa [2] 88 a4 [2] a3 88 [2] 8d aa [2] 99 b1 [2] 96 ab [2] 88 b6 [2] 8a b7 [2] 91 b1 [2] 8d b6 [2] 91 99 }

  condition:
    any of them
}