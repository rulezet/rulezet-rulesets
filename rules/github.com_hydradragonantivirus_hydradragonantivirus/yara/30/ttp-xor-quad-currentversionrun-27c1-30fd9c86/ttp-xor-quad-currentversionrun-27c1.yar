rule TTP_XOR_QUAD_CurrentVersionRun_27c1 {
  strings:
    $key_27c1 = { 74 ae [2] 50 a0 [2] 7b 8c [2] 55 ae [2] 41 b5 [2] 4e af [2] 50 b2 [2] 52 b3 [2] 49 b5 [2] 55 b2 [2] 49 9d }

  condition:
    any of them
}