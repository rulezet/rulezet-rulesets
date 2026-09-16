rule TTP_XOR_QUAD_CurrentVersionRun_cc6a {
  strings:
    $key_cc6a = { 9f 05 [2] bb 0b [2] 90 27 [2] be 05 [2] aa 1e [2] a5 04 [2] bb 19 [2] b9 18 [2] a2 1e [2] be 19 [2] a2 36 }

  condition:
    any of them
}