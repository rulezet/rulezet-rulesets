rule TTP_XOR_QUAD_CurrentVersionRun_cc07 {
  strings:
    $key_cc07 = { 9f 68 [2] bb 66 [2] 90 4a [2] be 68 [2] aa 73 [2] a5 69 [2] bb 74 [2] b9 75 [2] a2 73 [2] be 74 [2] a2 5b }

  condition:
    any of them
}