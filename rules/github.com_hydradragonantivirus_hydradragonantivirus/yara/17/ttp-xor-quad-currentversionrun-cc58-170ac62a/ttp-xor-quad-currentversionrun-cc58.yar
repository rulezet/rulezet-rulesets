rule TTP_XOR_QUAD_CurrentVersionRun_cc58 {
  strings:
    $key_cc58 = { 9f 37 [2] bb 39 [2] 90 15 [2] be 37 [2] aa 2c [2] a5 36 [2] bb 2b [2] b9 2a [2] a2 2c [2] be 2b [2] a2 04 }

  condition:
    any of them
}