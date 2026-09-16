rule TTP_XOR_QUAD_CurrentVersionRun_cc64 {
  strings:
    $key_cc64 = { 9f 0b [2] bb 05 [2] 90 29 [2] be 0b [2] aa 10 [2] a5 0a [2] bb 17 [2] b9 16 [2] a2 10 [2] be 17 [2] a2 38 }

  condition:
    any of them
}