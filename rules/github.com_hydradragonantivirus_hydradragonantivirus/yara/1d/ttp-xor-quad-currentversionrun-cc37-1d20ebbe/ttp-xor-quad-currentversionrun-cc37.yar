rule TTP_XOR_QUAD_CurrentVersionRun_cc37 {
  strings:
    $key_cc37 = { 9f 58 [2] bb 56 [2] 90 7a [2] be 58 [2] aa 43 [2] a5 59 [2] bb 44 [2] b9 45 [2] a2 43 [2] be 44 [2] a2 6b }

  condition:
    any of them
}