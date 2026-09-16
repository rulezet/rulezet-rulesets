rule TTP_XOR_QUAD_CurrentVersionRun_ede7 {
  strings:
    $key_ede7 = { be 88 [2] 9a 86 [2] b1 aa [2] 9f 88 [2] 8b 93 [2] 84 89 [2] 9a 94 [2] 98 95 [2] 83 93 [2] 9f 94 [2] 83 bb }

  condition:
    any of them
}