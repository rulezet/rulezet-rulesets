rule TTP_XOR_QUAD_CurrentVersionRun_cc68 {
  strings:
    $key_cc68 = { 9f 07 [2] bb 09 [2] 90 25 [2] be 07 [2] aa 1c [2] a5 06 [2] bb 1b [2] b9 1a [2] a2 1c [2] be 1b [2] a2 34 }

  condition:
    any of them
}