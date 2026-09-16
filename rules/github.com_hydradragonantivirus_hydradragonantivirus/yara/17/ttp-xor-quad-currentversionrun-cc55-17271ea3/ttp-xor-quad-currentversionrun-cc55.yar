rule TTP_XOR_QUAD_CurrentVersionRun_cc55 {
  strings:
    $key_cc55 = { 9f 3a [2] bb 34 [2] 90 18 [2] be 3a [2] aa 21 [2] a5 3b [2] bb 26 [2] b9 27 [2] a2 21 [2] be 26 [2] a2 09 }

  condition:
    any of them
}