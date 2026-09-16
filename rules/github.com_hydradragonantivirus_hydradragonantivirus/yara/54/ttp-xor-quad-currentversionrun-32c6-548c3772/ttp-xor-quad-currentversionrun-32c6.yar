rule TTP_XOR_QUAD_CurrentVersionRun_32c6 {
  strings:
    $key_32c6 = { 61 a9 [2] 45 a7 [2] 6e 8b [2] 40 a9 [2] 54 b2 [2] 5b a8 [2] 45 b5 [2] 47 b4 [2] 5c b2 [2] 40 b5 [2] 5c 9a }

  condition:
    any of them
}