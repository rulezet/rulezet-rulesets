rule TTP_XOR_QUAD_CurrentVersionRun_ccd5 {
  strings:
    $key_ccd5 = { 9f ba [2] bb b4 [2] 90 98 [2] be ba [2] aa a1 [2] a5 bb [2] bb a6 [2] b9 a7 [2] a2 a1 [2] be a6 [2] a2 89 }

  condition:
    any of them
}