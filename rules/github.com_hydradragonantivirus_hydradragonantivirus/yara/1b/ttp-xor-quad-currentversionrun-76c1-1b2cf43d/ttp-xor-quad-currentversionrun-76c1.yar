rule TTP_XOR_QUAD_CurrentVersionRun_76c1 {
  strings:
    $key_76c1 = { 25 ae [2] 01 a0 [2] 2a 8c [2] 04 ae [2] 10 b5 [2] 1f af [2] 01 b2 [2] 03 b3 [2] 18 b5 [2] 04 b2 [2] 18 9d }

  condition:
    any of them
}