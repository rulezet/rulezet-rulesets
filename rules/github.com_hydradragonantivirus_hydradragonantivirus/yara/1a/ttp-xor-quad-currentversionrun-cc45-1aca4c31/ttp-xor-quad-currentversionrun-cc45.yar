rule TTP_XOR_QUAD_CurrentVersionRun_cc45 {
  strings:
    $key_cc45 = { 9f 2a [2] bb 24 [2] 90 08 [2] be 2a [2] aa 31 [2] a5 2b [2] bb 36 [2] b9 37 [2] a2 31 [2] be 36 [2] a2 19 }

  condition:
    any of them
}