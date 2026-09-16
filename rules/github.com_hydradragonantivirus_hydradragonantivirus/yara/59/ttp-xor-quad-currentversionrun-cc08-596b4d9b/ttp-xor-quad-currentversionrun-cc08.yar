rule TTP_XOR_QUAD_CurrentVersionRun_cc08 {
  strings:
    $key_cc08 = { 9f 67 [2] bb 69 [2] 90 45 [2] be 67 [2] aa 7c [2] a5 66 [2] bb 7b [2] b9 7a [2] a2 7c [2] be 7b [2] a2 54 }

  condition:
    any of them
}