rule TTP_XOR_QUAD_CurrentVersionRun_7ccc {
  strings:
    $key_7ccc = { 2f a3 [2] 0b ad [2] 20 81 [2] 0e a3 [2] 1a b8 [2] 15 a2 [2] 0b bf [2] 09 be [2] 12 b8 [2] 0e bf [2] 12 90 }

  condition:
    any of them
}