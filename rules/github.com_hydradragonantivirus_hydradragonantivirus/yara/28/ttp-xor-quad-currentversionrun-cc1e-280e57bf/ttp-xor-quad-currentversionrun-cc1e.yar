rule TTP_XOR_QUAD_CurrentVersionRun_cc1e {
  strings:
    $key_cc1e = { 9f 71 [2] bb 7f [2] 90 53 [2] be 71 [2] aa 6a [2] a5 70 [2] bb 6d [2] b9 6c [2] a2 6a [2] be 6d [2] a2 42 }

  condition:
    any of them
}