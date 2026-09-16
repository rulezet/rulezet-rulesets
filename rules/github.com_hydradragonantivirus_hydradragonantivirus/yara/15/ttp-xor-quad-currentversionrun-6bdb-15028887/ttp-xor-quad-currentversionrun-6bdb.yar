rule TTP_XOR_QUAD_CurrentVersionRun_6bdb {
  strings:
    $key_6bdb = { 38 b4 [2] 1c ba [2] 37 96 [2] 19 b4 [2] 0d af [2] 02 b5 [2] 1c a8 [2] 1e a9 [2] 05 af [2] 19 a8 [2] 05 87 }

  condition:
    any of them
}