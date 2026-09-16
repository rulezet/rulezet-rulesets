rule TTP_XOR_QUAD_CurrentVersionRun_4ccc {
  strings:
    $key_4ccc = { 1f a3 [2] 3b ad [2] 10 81 [2] 3e a3 [2] 2a b8 [2] 25 a2 [2] 3b bf [2] 39 be [2] 22 b8 [2] 3e bf [2] 22 90 }

  condition:
    any of them
}