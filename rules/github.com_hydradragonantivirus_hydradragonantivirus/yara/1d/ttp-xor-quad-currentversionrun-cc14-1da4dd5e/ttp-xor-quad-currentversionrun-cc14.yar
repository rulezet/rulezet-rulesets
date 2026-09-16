rule TTP_XOR_QUAD_CurrentVersionRun_cc14 {
  strings:
    $key_cc14 = { 9f 7b [2] bb 75 [2] 90 59 [2] be 7b [2] aa 60 [2] a5 7a [2] bb 67 [2] b9 66 [2] a2 60 [2] be 67 [2] a2 48 }

  condition:
    any of them
}