rule TTP_XOR_QUAD_CurrentVersionRun_cc6b {
  strings:
    $key_cc6b = { 9f 04 [2] bb 0a [2] 90 26 [2] be 04 [2] aa 1f [2] a5 05 [2] bb 18 [2] b9 19 [2] a2 1f [2] be 18 [2] a2 37 }

  condition:
    any of them
}