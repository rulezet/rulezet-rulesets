rule TTP_XOR_QUAD_CurrentVersionRun_cc18 {
  strings:
    $key_cc18 = { 9f 77 [2] bb 79 [2] 90 55 [2] be 77 [2] aa 6c [2] a5 76 [2] bb 6b [2] b9 6a [2] a2 6c [2] be 6b [2] a2 44 }

  condition:
    any of them
}