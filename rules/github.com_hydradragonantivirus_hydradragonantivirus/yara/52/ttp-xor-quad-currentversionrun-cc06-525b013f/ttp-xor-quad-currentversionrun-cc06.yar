rule TTP_XOR_QUAD_CurrentVersionRun_cc06 {
  strings:
    $key_cc06 = { 9f 69 [2] bb 67 [2] 90 4b [2] be 69 [2] aa 72 [2] a5 68 [2] bb 75 [2] b9 74 [2] a2 72 [2] be 75 [2] a2 5a }

  condition:
    any of them
}