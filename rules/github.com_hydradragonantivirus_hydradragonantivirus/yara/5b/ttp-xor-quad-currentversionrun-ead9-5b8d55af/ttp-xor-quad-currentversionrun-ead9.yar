rule TTP_XOR_QUAD_CurrentVersionRun_ead9 {
  strings:
    $key_ead9 = { b9 b6 [2] 9d b8 [2] b6 94 [2] 98 b6 [2] 8c ad [2] 83 b7 [2] 9d aa [2] 9f ab [2] 84 ad [2] 98 aa [2] 84 85 }

  condition:
    any of them
}