rule TTP_XOR_QUAD_CurrentVersionRun_d8e7 {
  strings:
    $key_d8e7 = { 8b 88 [2] af 86 [2] 84 aa [2] aa 88 [2] be 93 [2] b1 89 [2] af 94 [2] ad 95 [2] b6 93 [2] aa 94 [2] b6 bb }

  condition:
    any of them
}