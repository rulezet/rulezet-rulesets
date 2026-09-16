rule TTP_XOR_QUAD_CurrentVersionRun_cc69 {
  strings:
    $key_cc69 = { 9f 06 [2] bb 08 [2] 90 24 [2] be 06 [2] aa 1d [2] a5 07 [2] bb 1a [2] b9 1b [2] a2 1d [2] be 1a [2] a2 35 }

  condition:
    any of them
}