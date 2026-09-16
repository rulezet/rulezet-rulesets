rule TTP_XOR_QUAD_CurrentVersionRun_cc59 {
  strings:
    $key_cc59 = { 9f 36 [2] bb 38 [2] 90 14 [2] be 36 [2] aa 2d [2] a5 37 [2] bb 2a [2] b9 2b [2] a2 2d [2] be 2a [2] a2 05 }

  condition:
    any of them
}