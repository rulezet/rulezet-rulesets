rule TTP_XOR_QUAD_CurrentVersionRun_30ca {
  strings:
    $key_30ca = { 63 a5 [2] 47 ab [2] 6c 87 [2] 42 a5 [2] 56 be [2] 59 a4 [2] 47 b9 [2] 45 b8 [2] 5e be [2] 42 b9 [2] 5e 96 }

  condition:
    any of them
}