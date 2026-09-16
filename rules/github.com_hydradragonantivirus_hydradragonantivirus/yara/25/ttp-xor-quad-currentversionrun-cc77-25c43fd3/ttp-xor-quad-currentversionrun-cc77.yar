rule TTP_XOR_QUAD_CurrentVersionRun_cc77 {
  strings:
    $key_cc77 = { 9f 18 [2] bb 16 [2] 90 3a [2] be 18 [2] aa 03 [2] a5 19 [2] bb 04 [2] b9 05 [2] a2 03 [2] be 04 [2] a2 2b }

  condition:
    any of them
}