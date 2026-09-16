rule TTP_XOR_QUAD_CurrentVersionRun_6bc7 {
  strings:
    $key_6bc7 = { 38 a8 [2] 1c a6 [2] 37 8a [2] 19 a8 [2] 0d b3 [2] 02 a9 [2] 1c b4 [2] 1e b5 [2] 05 b3 [2] 19 b4 [2] 05 9b }

  condition:
    any of them
}