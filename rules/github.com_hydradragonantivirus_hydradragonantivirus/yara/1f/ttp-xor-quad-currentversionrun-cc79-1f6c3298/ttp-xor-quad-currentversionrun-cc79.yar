rule TTP_XOR_QUAD_CurrentVersionRun_cc79 {
  strings:
    $key_cc79 = { 9f 16 [2] bb 18 [2] 90 34 [2] be 16 [2] aa 0d [2] a5 17 [2] bb 0a [2] b9 0b [2] a2 0d [2] be 0a [2] a2 25 }

  condition:
    any of them
}