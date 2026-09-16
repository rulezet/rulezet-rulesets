rule TTP_XOR_QUAD_CurrentVersionRun_eac5 {
  strings:
    $key_eac5 = { b9 aa [2] 9d a4 [2] b6 88 [2] 98 aa [2] 8c b1 [2] 83 ab [2] 9d b6 [2] 9f b7 [2] 84 b1 [2] 98 b6 [2] 84 99 }

  condition:
    any of them
}