rule TTP_XOR_QUAD_CurrentVersionRun_7bdb {
  strings:
    $key_7bdb = { 28 b4 [2] 0c ba [2] 27 96 [2] 09 b4 [2] 1d af [2] 12 b5 [2] 0c a8 [2] 0e a9 [2] 15 af [2] 09 a8 [2] 15 87 }

  condition:
    any of them
}