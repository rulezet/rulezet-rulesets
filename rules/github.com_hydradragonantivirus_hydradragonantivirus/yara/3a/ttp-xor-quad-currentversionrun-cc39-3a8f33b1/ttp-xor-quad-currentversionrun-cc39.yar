rule TTP_XOR_QUAD_CurrentVersionRun_cc39 {
  strings:
    $key_cc39 = { 9f 56 [2] bb 58 [2] 90 74 [2] be 56 [2] aa 4d [2] a5 57 [2] bb 4a [2] b9 4b [2] a2 4d [2] be 4a [2] a2 65 }

  condition:
    any of them
}