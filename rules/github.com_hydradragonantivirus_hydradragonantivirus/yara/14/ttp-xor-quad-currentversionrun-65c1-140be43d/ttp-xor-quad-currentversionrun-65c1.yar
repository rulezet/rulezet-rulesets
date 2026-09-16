rule TTP_XOR_QUAD_CurrentVersionRun_65c1 {
  strings:
    $key_65c1 = { 36 ae [2] 12 a0 [2] 39 8c [2] 17 ae [2] 03 b5 [2] 0c af [2] 12 b2 [2] 10 b3 [2] 0b b5 [2] 17 b2 [2] 0b 9d }

  condition:
    any of them
}