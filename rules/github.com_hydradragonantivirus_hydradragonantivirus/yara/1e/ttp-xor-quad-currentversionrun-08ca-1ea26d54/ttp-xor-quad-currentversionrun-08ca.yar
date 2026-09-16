rule TTP_XOR_QUAD_CurrentVersionRun_08ca {
  strings:
    $key_08ca = { 5b a5 [2] 7f ab [2] 54 87 [2] 7a a5 [2] 6e be [2] 61 a4 [2] 7f b9 [2] 7d b8 [2] 66 be [2] 7a b9 [2] 66 96 }

  condition:
    any of them
}