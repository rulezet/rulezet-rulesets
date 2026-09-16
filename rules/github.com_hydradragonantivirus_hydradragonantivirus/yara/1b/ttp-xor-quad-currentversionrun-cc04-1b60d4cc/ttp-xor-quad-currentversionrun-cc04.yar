rule TTP_XOR_QUAD_CurrentVersionRun_cc04 {
  strings:
    $key_cc04 = { 9f 6b [2] bb 65 [2] 90 49 [2] be 6b [2] aa 70 [2] a5 6a [2] bb 77 [2] b9 76 [2] a2 70 [2] be 77 [2] a2 58 }

  condition:
    any of them
}