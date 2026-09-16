rule TTP_XOR_QUAD_CurrentVersionRun_2bc7 {
  strings:
    $key_2bc7 = { 78 a8 [2] 5c a6 [2] 77 8a [2] 59 a8 [2] 4d b3 [2] 42 a9 [2] 5c b4 [2] 5e b5 [2] 45 b3 [2] 59 b4 [2] 45 9b }

  condition:
    any of them
}