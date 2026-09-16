rule TTP_XOR_QUAD_CurrentVersionRun_fce7 {
  strings:
    $key_fce7 = { af 88 [2] 8b 86 [2] a0 aa [2] 8e 88 [2] 9a 93 [2] 95 89 [2] 8b 94 [2] 89 95 [2] 92 93 [2] 8e 94 [2] 92 bb }

  condition:
    any of them
}