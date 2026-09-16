rule TTP_XOR_QUAD_CurrentVersionRun_cc38 {
  strings:
    $key_cc38 = { 9f 57 [2] bb 59 [2] 90 75 [2] be 57 [2] aa 4c [2] a5 56 [2] bb 4b [2] b9 4a [2] a2 4c [2] be 4b [2] a2 64 }

  condition:
    any of them
}