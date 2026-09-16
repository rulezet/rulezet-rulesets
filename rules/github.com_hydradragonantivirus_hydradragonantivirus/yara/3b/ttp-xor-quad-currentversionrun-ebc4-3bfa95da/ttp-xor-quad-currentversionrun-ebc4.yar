rule TTP_XOR_QUAD_CurrentVersionRun_ebc4 {
  strings:
    $key_ebc4 = { b8 ab [2] 9c a5 [2] b7 89 [2] 99 ab [2] 8d b0 [2] 82 aa [2] 9c b7 [2] 9e b6 [2] 85 b0 [2] 99 b7 [2] 85 98 }

  condition:
    any of them
}