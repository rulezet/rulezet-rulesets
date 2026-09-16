rule TTP_XOR_QUAD_CurrentVersionRun_ebe7 {
  strings:
    $key_ebe7 = { b8 88 [2] 9c 86 [2] b7 aa [2] 99 88 [2] 8d 93 [2] 82 89 [2] 9c 94 [2] 9e 95 [2] 85 93 [2] 99 94 [2] 85 bb }

  condition:
    any of them
}