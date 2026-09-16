rule TTP_XOR_QUAD_CurrentVersionRun_cc28 {
  strings:
    $key_cc28 = { 9f 47 [2] bb 49 [2] 90 65 [2] be 47 [2] aa 5c [2] a5 46 [2] bb 5b [2] b9 5a [2] a2 5c [2] be 5b [2] a2 74 }

  condition:
    any of them
}