rule TTP_XOR_QUAD_CurrentVersionRun_07c1 {
  strings:
    $key_07c1 = { 54 ae [2] 70 a0 [2] 5b 8c [2] 75 ae [2] 61 b5 [2] 6e af [2] 70 b2 [2] 72 b3 [2] 69 b5 [2] 75 b2 [2] 69 9d }

  condition:
    any of them
}