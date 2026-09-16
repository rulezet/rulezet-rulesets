rule TTP_XOR_QUAD_CurrentVersionRun_cc09 {
  strings:
    $key_cc09 = { 9f 66 [2] bb 68 [2] 90 44 [2] be 66 [2] aa 7d [2] a5 67 [2] bb 7a [2] b9 7b [2] a2 7d [2] be 7a [2] a2 55 }

  condition:
    any of them
}