rule TTP_XOR_QUAD_CurrentVersionRun_cc67 {
  strings:
    $key_cc67 = { 9f 08 [2] bb 06 [2] 90 2a [2] be 08 [2] aa 13 [2] a5 09 [2] bb 14 [2] b9 15 [2] a2 13 [2] be 14 [2] a2 3b }

  condition:
    any of them
}