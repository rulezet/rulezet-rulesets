rule TTP_XOR_QUAD_CurrentVersionRun_32c7 {
  strings:
    $key_32c7 = { 61 a8 [2] 45 a6 [2] 6e 8a [2] 40 a8 [2] 54 b3 [2] 5b a9 [2] 45 b4 [2] 47 b5 [2] 5c b3 [2] 40 b4 [2] 5c 9b }

  condition:
    any of them
}