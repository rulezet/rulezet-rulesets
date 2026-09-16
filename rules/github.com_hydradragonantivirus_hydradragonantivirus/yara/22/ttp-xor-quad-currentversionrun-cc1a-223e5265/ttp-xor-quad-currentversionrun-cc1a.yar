rule TTP_XOR_QUAD_CurrentVersionRun_cc1a {
  strings:
    $key_cc1a = { 9f 75 [2] bb 7b [2] 90 57 [2] be 75 [2] aa 6e [2] a5 74 [2] bb 69 [2] b9 68 [2] a2 6e [2] be 69 [2] a2 46 }

  condition:
    any of them
}