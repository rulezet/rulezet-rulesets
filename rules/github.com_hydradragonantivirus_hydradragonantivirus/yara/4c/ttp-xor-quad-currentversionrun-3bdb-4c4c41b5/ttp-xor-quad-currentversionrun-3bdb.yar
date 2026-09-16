rule TTP_XOR_QUAD_CurrentVersionRun_3bdb {
  strings:
    $key_3bdb = { 68 b4 [2] 4c ba [2] 67 96 [2] 49 b4 [2] 5d af [2] 52 b5 [2] 4c a8 [2] 4e a9 [2] 55 af [2] 49 a8 [2] 55 87 }

  condition:
    any of them
}