rule TTP_XOR_QUAD_CurrentVersionRun_ebdb {
  strings:
    $key_ebdb = { b8 b4 [2] 9c ba [2] b7 96 [2] 99 b4 [2] 8d af [2] 82 b5 [2] 9c a8 [2] 9e a9 [2] 85 af [2] 99 a8 [2] 85 87 }

  condition:
    any of them
}