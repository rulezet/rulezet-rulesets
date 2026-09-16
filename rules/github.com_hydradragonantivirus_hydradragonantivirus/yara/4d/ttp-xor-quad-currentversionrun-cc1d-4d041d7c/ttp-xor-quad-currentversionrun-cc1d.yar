rule TTP_XOR_QUAD_CurrentVersionRun_cc1d {
  strings:
    $key_cc1d = { 9f 72 [2] bb 7c [2] 90 50 [2] be 72 [2] aa 69 [2] a5 73 [2] bb 6e [2] b9 6f [2] a2 69 [2] be 6e [2] a2 41 }

  condition:
    any of them
}